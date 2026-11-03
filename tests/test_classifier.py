"""Offline unit tests for the TOML-driven classifier.

These exercise the rule engine against the real DefaultRules/ ruleset with no
network, no SMB server, and no root required:

    pytest tests/test_classifier.py -v
"""

import pytest

from snaffcore.classifier import (
    Rules,
    is_interest_share,
    classify_directory,
    classify_file_name,
    classify_file_content,
    check_for_keys,
)


class FakeFile:
    """Minimal stand-in for RemoteFile (classifier only reads these attrs)."""

    def __init__(self, name, share="share", target="10.0.0.1", size=100):
        self.name = name
        self.share = share
        self.target = target
        self.size = size


@pytest.fixture(scope="module")
def rules():
    r = Rules()
    r.prepare_classifiers()
    return r


def action(result):
    return result.get("action") if result else None


# --- loading -------------------------------------------------------------

def test_rules_loaded(rules):
    assert len(rules.file_classifiers) > 0
    assert len(rules.share_classifiers) > 0
    assert len(rules.contents_classifiers) > 0
    # Content rules must be indexed by name so Relay lookups work.
    assert rules.contents_by_name


def test_discard_sorted_first(rules):
    for bucket in (rules.share_classifiers, rules.directory_classifiers,
                   rules.file_classifiers):
        actions = [r.get("MatchAction") for r in bucket]
        discards = [i for i, a in enumerate(actions) if a == "Discard"]
        keeps = [i for i, a in enumerate(actions) if a != "Discard"]
        if discards and keeps:
            assert max(discards) < min(keeps)


# --- shares --------------------------------------------------------------

@pytest.mark.parametrize("share,keep", [
    ("IPC$", False),
    ("print$", False),
    ("C$", True),      # matched by a Snaffle rule
    ("hr", True),      # unknown share -> kept by default
])
def test_share_classification(rules, share, keep):
    assert is_interest_share(share, rules) is keep


# --- directories ---------------------------------------------------------

@pytest.mark.parametrize("path,descend", [
    (r"\\h\\c\\Windows\\system32\\drivers", False),
    (r"\\h\\c\\app\\node_modules\\x", False),
    (r"\\h\\c\\Users\\bob\\Documents", True),
])
def test_directory_classification(rules, path, descend):
    assert classify_directory(path, rules) is descend


# --- file name / extension / path ---------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("photo.jpg", "Discard"),
    ("secret.ppk", "Snaffle"),
    (".htpasswd", "Snaffle"),
    ("notes.txt", "Relay"),
    ("cert.pfx", "CheckForKeys"),
    ("boring.dll", None),
])
def test_file_name_classification(rules, name, expected):
    assert action(classify_file_name(FakeFile(name), rules)) == expected


def test_id_rsa_is_interesting(rules):
    assert classify_file_name(FakeFile("id_rsa"), rules) is not None


def test_postmatch_suppresses_known_false_positive(rules):
    res = classify_file_name(FakeFile("psexec.exe"), rules)
    assert res is None or res.get("action") == "Discard"


# --- content (Relay target rules) ---------------------------------------

def test_relay_then_content_match(rules):
    relay = classify_file_name(FakeFile("app.config"), rules)
    assert action(relay) == "Relay"
    hit = classify_file_content(
        FakeFile("app.config"), 'password = "Sup3rSecret!"',
        rules, relay.get("targets"))
    assert hit is not None


def test_content_no_false_positive(rules):
    relay = classify_file_name(FakeFile("app.config"), rules)
    hit = classify_file_content(
        FakeFile("app.config"), "nothing sensitive here\njust text\n",
        rules, relay.get("targets"))
    assert hit is None


# --- SSN / PII content rule -------------------------------------------------

@pytest.mark.parametrize("name", ["employees.csv", "notes.txt", "dump.sql"])
def test_ssn_relay_routes_document_types(rules, name):
    relay = classify_file_name(FakeFile(name), rules)
    assert action(relay) == "Relay"
    assert "KeepSsnInFile" in relay.get("targets", [])


def test_config_relay_union_includes_ssn(rules):
    # app.config matches both the generic config relay and the PII relay; the
    # union of their targets must still include the SSN check.
    relay = classify_file_name(FakeFile("app.config"), rules)
    assert "KeepSsnInFile" in relay.get("targets", [])


def test_ssn_detected_in_content(rules):
    relay = classify_file_name(FakeFile("employees.csv"), rules)
    hit = classify_file_content(
        FakeFile("employees.csv"), "name,ssn\nBob,123-45-6789\n",
        rules, relay.get("targets"))
    assert hit is not None and hit["RuleName"] == "KeepSsnInFile"


@pytest.mark.parametrize("text", [
    "call me at 555-1234 tomorrow",     # too short
    "order 1234-56-78901 shipped",       # wrong digit grouping
    "no numbers here at all",
])
def test_ssn_no_false_positive(rules, text):
    relay = classify_file_name(FakeFile("notes.txt"), rules)
    assert classify_file_content(
        FakeFile("notes.txt"), text, rules, relay.get("targets")) is None


# --- CheckForKeys --------------------------------------------------------

_RULE = {"Triage": "Red", "RuleName": "t", "Description": "d"}


def test_pem_private_key_detected(rules):
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    assert check_for_keys(FakeFile("server.pem"), pem, _RULE) is not None


def test_pem_without_key_ignored(rules):
    assert check_for_keys(FakeFile("server.pem"), "no key here", _RULE) is None


def test_binary_keystore_assumed_interesting(rules):
    assert check_for_keys(FakeFile("store.pfx"), "", _RULE) is not None
