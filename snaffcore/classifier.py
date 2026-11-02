import re
import os
import logging
import termcolor

from .file_handling import *

log = logging.getLogger('snafflepy.classifier')


# TOML loader: prefer the stdlib tomllib (Python 3.11+), fall back to the
# third-party `toml` package that is listed in requirements.txt.
try:
    import tomllib  # type: ignore

    def _load_toml(path):
        with open(path, 'rb') as f:
            return tomllib.load(f)
except ImportError:  # pragma: no cover - depends on interpreter version
    import toml

    def _load_toml(path):
        with open(path, 'r', encoding='utf-8') as f:
            return toml.load(f)


# Snaffler Triage levels mapped to a (text_color, background) pair understood
# by termcolor. These describe how "interesting" a finding is.
TRIAGE_COLORS = {
    "black": ("white", "on_dark_grey"),
    "green": ("green", "on_white"),
    "yellow": ("yellow", "on_white"),
    "red": ("red", "on_white"),
}

VALID_SCOPES = {
    "ShareEnumeration",
    "DirectoryEnumeration",
    "FileEnumeration",
    "ContentsEnumeration",
    "PostMatch",
}

VALID_WORDLIST_TYPES = {"Exact", "Contains", "StartsWith", "EndsWith", "Regex"}


def _triage_print(prefix, subject, rule):
    """Pretty-print a matched finding using the rule's Triage colour."""
    triage = str(rule.get('Triage', 'Green')).lower()
    text_color, on_color = TRIAGE_COLORS.get(triage, ("green", "on_white"))
    body = f"{{{rule.get('Triage', 'Green')}}} {subject} " \
           f"<{rule.get('RuleName', '?')}>:<{rule.get('Description', '')}>"
    print(prefix, termcolor.colored(body, text_color, on_color))


class Rules:
    """Loads Snaffler-style TOML classifier rules and sorts them by scope."""

    def __init__(self) -> None:
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []
        # ContentsEnumeration rules indexed by RuleName so Relay rules can
        # look up the specific content checks they reference.
        self.contents_by_name = {}

    def prepare_classifiers(self, rules_dir=None):
        if rules_dir is None:
            # Resolve relative to this module so SnafflePy works regardless of
            # the current working directory it is launched from.
            rules_dir = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), "DefaultRules")

        if not os.path.isdir(rules_dir):
            log.error(f"Rules directory not found: {rules_dir}")
            return

        rule_count = 0
        for root, _dirs, files in os.walk(rules_dir):
            for name in files:
                if not name.lower().endswith(".toml"):
                    continue
                path = os.path.join(root, name)
                try:
                    toml_loaded = _load_toml(path)
                except Exception as e:
                    log.warning(f"Failed to parse rule file {path}: {e}")
                    continue

                for dict_rule in toml_loaded.get('ClassifierRules', []):
                    if self._register_rule(dict_rule, path):
                        rule_count += 1

        self._sort_discard_first()
        log.info(f"Loaded {rule_count} classifier rules from {rules_dir}")
        log.debug(
            f"share={len(self.share_classifiers)} dir={len(self.directory_classifiers)} "
            f"file={len(self.file_classifiers)} contents={len(self.contents_classifiers)} "
            f"postmatch={len(self.postmatch_classifiers)}")

    def _register_rule(self, rule, path):
        scope = rule.get('EnumerationScope')
        name = rule.get('RuleName', '<unnamed>')

        if scope not in VALID_SCOPES:
            log.warning(
                f"{name} in {path} has invalid EnumerationScope '{scope}', skipping")
            return False

        # WordListType is required for every rule that carries a WordList.
        wl_type = rule.get('WordListType')
        if rule.get('WordList') is not None and wl_type not in VALID_WORDLIST_TYPES:
            log.warning(
                f"{name} has invalid WordListType '{wl_type}' - valid values are "
                f"{', '.join(sorted(VALID_WORDLIST_TYPES))}, skipping")
            return False

        # Pre-compile the regexes once so matching stays fast.
        try:
            rule['_compiled'] = self._compile_patterns(rule)
        except re.error as e:
            log.warning(f"{name} has an invalid regex pattern ({e}), skipping")
            return False

        if scope == "ShareEnumeration":
            self.share_classifiers.append(rule)
        elif scope == "DirectoryEnumeration":
            self.directory_classifiers.append(rule)
        elif scope == "FileEnumeration":
            self.file_classifiers.append(rule)
        elif scope == "ContentsEnumeration":
            self.contents_classifiers.append(rule)
            self.contents_by_name[rule.get('RuleName')] = rule
        elif scope == "PostMatch":
            self.postmatch_classifiers.append(rule)
        return True

    def _sort_discard_first(self):
        # Discard rules are always evaluated before Keep/Snaffle rules, matching
        # Snaffler's "discard wins" precedence.
        for bucket in (self.share_classifiers, self.directory_classifiers,
                       self.file_classifiers):
            bucket.sort(key=lambda r: 0 if r.get('MatchAction') == "Discard" else 1)

    @staticmethod
    def _compile_patterns(rule):
        """Compile every WordList entry into an anchored, case-insensitive regex."""
        wl_type = rule.get('WordListType')
        compiled = []
        for pattern in rule.get('WordList', []) or []:
            pattern = str(pattern)
            if wl_type == "EndsWith":
                regex = pattern + "$"
            elif wl_type == "StartsWith":
                regex = "^" + pattern
            elif wl_type == "Exact":
                regex = "^" + pattern + "$"
            else:  # Contains or Regex
                regex = pattern
            compiled.append(re.compile(regex, re.IGNORECASE))
        return compiled


def _subject_for_location(location, *, share="", filename="", extension="",
                          filepath="", content=""):
    """Return the string a rule should be matched against for its MatchLocation."""
    return {
        "ShareName": share,
        "FileName": filename,
        "FileExtension": extension,
        "FilePath": filepath,
        "FileContentAsString": content,
        "FileContentAsBytes": content,
    }.get(location, filepath)


def _rule_matches(rule, subject):
    if not subject:
        return False
    for regex in rule.get('_compiled', []):
        if regex.search(subject) is not None:
            return True
    return False


# ---------------------------------------------------------------------------
# Share / directory classification
# ---------------------------------------------------------------------------

def is_interest_share(share, rules: Rules) -> bool:
    """Return True if a share should be scanned, False if it should be skipped.

    Discard rules win over Snaffle rules. If nothing matches we keep the share
    (so unknown shares still get scanned), which mirrors Snaffler's behaviour.
    """
    share_text = termcolor.colored("[Share]", 'light_yellow')
    for rule in rules.share_classifiers:
        subject = _subject_for_location(
            rule.get('MatchLocation', 'ShareName'), share=share, filepath=share)
        if _rule_matches(rule, subject):
            action = rule.get('MatchAction')
            if action == "Discard":
                log.debug(
                    f"{share} matched Discard rule {rule.get('RuleName')}, skipping")
                return False
            # Snaffle / Keep
            _triage_print(share_text, share, rule)
            return True
    return True


def classify_directory(dir_path, rules: Rules) -> bool:
    """Return True to descend into a directory, False to skip it."""
    for rule in rules.directory_classifiers:
        subject = _subject_for_location(
            rule.get('MatchLocation', 'FilePath'), filepath=dir_path)
        if _rule_matches(rule, subject):
            if rule.get('MatchAction') == "Discard":
                log.debug(
                    f"{dir_path} matched Discard rule {rule.get('RuleName')}, skipping dir")
                return False
            dir_text = termcolor.colored("[Directory]", 'light_blue')
            _triage_print(dir_text, dir_path, rule)
            return True
    return True


# ---------------------------------------------------------------------------
# File name / extension / path classification
# ---------------------------------------------------------------------------

def _file_subjects(file):
    """Derive (filename, extension, filepath) from a RemoteFile."""
    raw = str(file.name).replace('/', '\\')
    filename = raw.split('\\')[-1]
    _base, ext = os.path.splitext(filename)
    filepath = f"\\\\{file.target}\\{file.share}\\{raw}"
    return filename, ext, filepath


def _postmatch_discard(filename, filepath, rules: Rules) -> bool:
    """True if a post-match rule flags this as a known false positive."""
    for rule in rules.postmatch_classifiers:
        if rule.get('MatchAction') != "Discard":
            continue
        subject = _subject_for_location(
            rule.get('MatchLocation', 'FileName'),
            filename=filename, filepath=filepath)
        if _rule_matches(rule, subject):
            log.debug(
                f"{filename} suppressed by PostMatch rule {rule.get('RuleName')}")
            return True
    return False


def classify_file_name(file, rules: Rules):
    """Classify a file by name/extension/path using the TOML FileEnumeration rules.

    Returns a dict describing what to do:
      {'action': 'Discard'}                                 -> skip entirely
      {'action': 'Snaffle', 'rule': <rule>}                 -> keep/report & download
      {'action': 'Relay',   'rule': <rule>, 'targets':[..]} -> scan contents
      {'action': 'CheckForKeys', 'rule': <rule>}            -> parse for private keys
      None                                                  -> not interesting
    """
    filename, extension, filepath = _file_subjects(file)

    relay_match = None
    checkkeys_match = None

    for rule in rules.file_classifiers:
        subject = _subject_for_location(
            rule.get('MatchLocation', 'FileName'),
            filename=filename, extension=extension, filepath=filepath)
        if not _rule_matches(rule, subject):
            continue

        action = rule.get('MatchAction')
        if action == "Discard":
            # Discard rules are first in the list, so this wins immediately.
            return {'action': 'Discard', 'rule': rule}
        if action == "Snaffle":
            if _postmatch_discard(filename, filepath, rules):
                return {'action': 'Discard', 'rule': rule}
            file_text = termcolor.colored("[File]", 'green')
            _triage_print(file_text, filepath, rule)
            return {'action': 'Snaffle', 'rule': rule}
        if action == "Relay" and relay_match is None:
            relay_match = rule
        elif action == "CheckForKeys" and checkkeys_match is None:
            checkkeys_match = rule

    if relay_match is not None:
        return {'action': 'Relay', 'rule': relay_match,
                'targets': relay_match.get('RelayTargets', [])}
    if checkkeys_match is not None:
        return {'action': 'CheckForKeys', 'rule': checkkeys_match}
    return None


# ---------------------------------------------------------------------------
# File content classification
# ---------------------------------------------------------------------------

def classify_file_content(file, content, rules: Rules, target_rule_names=None):
    """Scan file contents against ContentsEnumeration rules.

    If target_rule_names is provided (from a Relay rule) only those content
    rules are evaluated; otherwise every content rule is tried.
    Returns the first matching rule, or None.
    """
    if content is None:
        return None

    if target_rule_names:
        candidates = [rules.contents_by_name[n]
                      for n in target_rule_names if n in rules.contents_by_name]
    else:
        candidates = rules.contents_classifiers

    _filename, _ext, filepath = _file_subjects(file)
    for rule in candidates:
        for regex in rule.get('_compiled', []):
            if regex.search(content) is not None:
                if rule.get('MatchAction') == "Discard":
                    return None
                file_text = termcolor.colored("[File]", 'green')
                _triage_print(file_text, filepath, rule)
                return rule
    return None


# Markers that indicate an inline private key inside a certificate/key file.
_PRIVATE_KEY_MARKERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
)


def check_for_keys(file, content, rule, raw_bytes=None):
    """Report a certificate/key file that actually contains a private key.

    PEM files are detected via their textual markers. Binary container formats
    (PFX/PKCS12/DER) are treated as interesting by default since they almost
    always ship a private key alongside the certificate.
    """
    _filename, ext, filepath = _file_subjects(file)
    has_key = False
    if content and any(m in content for m in _PRIVATE_KEY_MARKERS):
        has_key = True
    elif ext.lower() in (".pfx", ".p12", ".pk12", ".pkcs12", ".der"):
        # Binary keystores: can't cheaply confirm, assume present.
        has_key = True

    if has_key:
        file_text = termcolor.colored("[File]", 'green')
        _triage_print(file_text, filepath, rule)
        return rule
    return None
