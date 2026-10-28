import re
import toml
import os
import logging
# import pprint
import termcolor

from impacket.smbconnection import SessionError, SMBConnection
from .smb import *
from .file_handling import *

log = logging.getLogger('snafflepy.classifier')

# TODO


class Rules:

    def __init__(self) -> None:
        self.classifier_rules = []
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []

    def prepare_classifiers(self):
        share_path = "./snaffcore/DefaultRules/"

        for root, dirs, files in os.walk(share_path, topdown=False):
            for name in files:
                # print(os.path.join(root,name))
                with open(os.path.join(root, name), 'r') as tfile:
                    toml_loaded = toml.load(tfile)
                for dict_rule in toml_loaded['ClassifierRules']:
                    if dict_rule['EnumerationScope'] == "ShareEnumeration":
                        self.share_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "FileEnumeration":
                        self.file_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "DirectoryEnumeration":
                        self.directory_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "PostMatch":
                        self.postmatch_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "ContentsEnumeration":
                        self.contents_classifiers.append(dict_rule)
                    else:
                        log.warning(
                            f"{dict_rule['RuleName']} is invalid, please check your syntax!")

# TODO


def is_interest_file(file, smb_client, share, no_download: bool):
    backup_ext_list = [".bak", ".mdf", ".sqldump", ".sdf", ".dmp"]
    cred_list = ["creds", "password", "passw", "credentials", "login", "secret", "account", "pass",
                 ".kdb", ".psafe3", ".kwallet", ".keychain", ".agilekeychain", ".cred"]

    file_text = termcolor.colored(f"[File]", "green")
    ssn_regex = str(r"^\d{{3}}-\d{{2}}-\d{{4}}$")
    is_interest = False

    # Non-file shares
    # if str(share).lower().find("ipc") or str(share).lower().find("print"):
    #     pass
    # else:

    # MVP Build only, check for SSN in files

    # MVP Build only, check for backup files
    for ext in backup_ext_list:
        if re.search(str(ext), str(file.name).lower()):
            is_interest = True
            file_triage = termcolor.colored(
                f"{{Yellow}}\\\\{file.target}\\{share}\\{file.name} <KeepBackupFiles>", "light_yellow", "on_white")
            try:
                file.get(smb_client)
                log.info(f"{file_text} {file_triage}")
            except FileRetrievalError as e:
                file.handle_download_error(file.name, e, False, False)

    # MVP Build only, check for files with possible passwords contained inside
    for cred in cred_list:
        if re.search(str(cred), str(file.name).lower()):
            is_interest = True

            file_triage = termcolor.colored(
                f"{{Black}}\\\\{file.target}\\{share}\\{file.name} <KeepFilesWithInterestName>", "black", "on_white")
            try:
                if not no_download:
                    file.get(smb_client)
                log.info(f"{file_text} {file_triage}")
            except FileRetrievalError as e:
                file.handle_download_error(file.name, e, False, False)

    file_data = ""
    try:
        if not no_download:
            file.get(smb_client)
            with open(str(file.tmp_filename), 'rb') as f:
                file_data = str(f.read(10000))
                if re.search(ssn_regex, file_data):
                    file_triage = termcolor.colored(
                        f"{{Red}}\\\\{file.target}\\{share}\\{file.name} <SsnRegexFound>", "red", "on_white")
                    log.info(f"{file_text} {file_triage}")
                elif not is_interest:
                    # print(file.name)
                    os.remove(f"./{file.tmp_filename}")
        else:
            pass
    except FileRetrievalError as e:
        os.remove(f"./{file.tmp_filename}")
        file.handle_download_error(file.name, e, False, False)


# TODO 
# Implementing file name classification with snafflers ruleset here
# Going to follow the same steps as is_interest_share  
# Call this function after every file has been downloaded in order to avoid problems with nested directories
# Call it within the for targets loop but after the for share loop stage is over so it can still do multiple targets  
def classify_file_name(file, rules: Rules):
    for rule in rules.file_classifiers:
        pass

def classify_file_content(file, rules:Rules):
    for rule in rules.contents_classifiers:
        pass

def classify_directory(dir, rules:Rules):
    for rule in rules.directory_classifiers:
        regex_rules = []
        dir_text = termcolor.colored("[Share]", 'light_yellow')
        default_triage = termcolor.colored(f"{dir}", 'green')
        if rule['WordListType'] == "Regex":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(dir)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(dir_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {dir} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{dir} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "EndsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern + "$"), str(dir)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(dir_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {dir} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True

                    else:
                        log.debug(
                            f"{dir} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "StartsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern), str(dir)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(dir_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {dir} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True

                    else:
                        log.debug(
                            f"{dir} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "Contains":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(dir)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(dir_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {dir} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{rule['MatchAction']} {dir} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "Exact":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern + "$"), str(dir)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(dir_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {dir} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{dir} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        else:
            log.warning(
                f"{rule['RuleName']} has an invalid WordListType - valid values are Regex, EndsWith, StartsWith, Contains, or Exact")
            raise Exception("Invalid WordListType")


def is_interest_share(share, rules: Rules) -> bool:

    # Tedium City to find match in wordlist. Did not prepare rules beforehand except by putting each MatchLocation in its own list
    # so I have to do more work here before I can find the match

    for rule in rules.share_classifiers:
        regex_rules = []
        share_text = termcolor.colored("[Share]", 'light_yellow')
        default_triage = termcolor.colored(f"{share}", 'green')
        if rule['WordListType'] == "Regex":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{share} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "EndsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern + "$"), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True

                    else:
                        log.debug(
                            f"{share} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "StartsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True

                    else:
                        log.debug(
                            f"{share} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "Contains":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        elif rule['WordListType'] == "Exact":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern + "$"), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(
                            f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>", str(color).lower(), 'on_white'))
                        return True
                    else:
                        log.debug(
                            f"{share} matched rule {rule['RuleName']}:{rule['Description']}")
                        if rule['MatchAction'] == "Discard":
                            return False

        else:
            log.warning(
                f"{rule['RuleName']} has an invalid WordListType - valid values are Regex, EndsWith, StartsWith, Contains, or Exact")
            raise Exception("Invalid WordListType")
