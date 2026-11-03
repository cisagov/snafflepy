import os
import sys
import termcolor

from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE
# from .smb import * 
from .utilities import *
from .smb import SMBClient
from .file_handling import RemoteFile
from .classifier import *
from .errors import *

log = logging.getLogger('snafflepy')


def begin_snaffle(options):

    snaff_rules = Rules()
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    # Automatically get domain from target if not provided
    if not options.domain:
        options.domain = get_domain(options.targets[0])
        if options.domain == "":
            sys.exit(2)

    domain_names = []
    if options.disable_computer_discovery:
        log.info(
            "Computer discovery is turned off. Snaffling will only occur on the host(s) specified.")

    else:
        login = access_ldap_server(
            options.targets[0], options.username, options.password)
        domain_names = list_computers(login, options.domain)
        for target in domain_names:
            log.info(
                f"Found{target}, adding to targets to snaffle...")
            try:
                options.targets.append(target)
            except Exception as e:
                log.debug(f"Exception: {e}")
                log.warning(f"Unable to add{target} to targets to snaffle")
                continue

    if options.go_loud:
        log.warning(
            "[GO LOUD ACTIVATED] Enumerating all shares for all files...")
    if options.no_download:
        log.warning("[no-download] is turned on, skipping SSN check...")
        
    for target in options.targets:

        smb_client = SMBClient(
            target, options.username, options.password, options.domain, options.hash, options.shares)
        if not smb_client.login():
            log.error(f"Unable to login to {target}")
            continue

        for share in smb_client.shares:
            if not options.go_loud:
                if not is_interest_share(share, snaff_rules):
                    log.debug(
                        f"{share} matched a Discard rule, skipping files inside of this share...")
                    continue
            snaffle_directory(smb_client, share, "", target, snaff_rules, options)


def snaffle_directory(smb_client, share, path, target, rules, options):
    '''
    Recursively walk a share, classifying each directory and file against the
    loaded TOML rules. Directories are detected via SMB file attributes rather
    than by triggering download errors.
    '''
    try:
        entries = list(smb_client.ls(share, path))
    except FileListError as e:
        log.error(f"Cannot list files at \\\\{target}\\{share}\\{path} {e}")
        return

    for entry in entries:
        name = entry.get_longname()
        full = f"{path}\\{name}" if path else name

        if entry.is_directory():
            dir_path = f"\\\\{target}\\{share}\\{full}"
            if options.go_loud:
                dir_text = termcolor.colored("[Directory]", 'light_blue')
                log.info(f"{dir_text} {dir_path}")
            elif not classify_directory(dir_path, rules):
                continue
            snaffle_directory(smb_client, share, full, target, rules, options)
            continue

        size = entry.get_filesize()
        file = RemoteFile(full, share, target, size, smb_client)

        if options.go_loud:
            try:
                file_text = termcolor.colored("[File]", 'green')
                if not options.no_download:
                    file.get(smb_client)
                log.info(f"{file_text} \\\\{target}\\{share}\\{full}")
            except FileRetrievalError as e:
                log.debug(f"Could not retrieve {full}: {e}")
            continue

        try:
            process_file(file, smb_client, share, rules, options)
        except FileRetrievalError as e:
            log.debug(f"Could not process {full}: {e}")


def process_file(file, smb_client, share, rules, options):
    '''
    Classify a single file by name/extension/path, then (for Relay and
    CheckForKeys matches) download it and scan its contents.
    '''
    result = classify_file_name(file, rules)
    if not result or result['action'] == "Discard":
        return

    action = result['action']
    oversized = file.size >= options.max_file_snaffle

    if action == "Snaffle":
        # The finding has already been printed by the classifier. Grab a copy
        # unless the user asked us not to, or the file is too large.
        if not options.no_download and not oversized:
            file.get(smb_client)
        return

    # Relay / CheckForKeys both need the file contents.
    if options.no_download or oversized:
        log.debug(
            f"Skipping content scan of {file.name} (no-download or over max size)")
        return

    file.get(smb_client)
    content = _read_text(file.tmp_filename)

    if action == "Relay":
        matched = classify_file_content(
            file, content, rules, result.get('targets'))
    else:  # CheckForKeys
        matched = check_for_keys(file, content, result['rule'])

    if matched is None:
        # Nothing interesting inside - don't keep the local copy around.
        _safe_remove(file.tmp_filename)


def _read_text(path):
    try:
        with open(str(path), 'rb') as f:
            return f.read().decode('utf-8', errors='replace')
    except OSError as e:
        log.debug(f"Could not read downloaded file {path}: {e}")
        return ""


def _safe_remove(path):
    try:
        os.remove(str(path))
    except OSError:
        pass

def access_ldap_server(ip, username, password):
    # log.info("Accessing LDAP Server")
    server = Server(ip, get_info=DSA)
    try:
        conn = Connection(server, username, password)
        # log.debug(server.schema)

        if not conn.bind():
            log.critical(f"Unable to bind to {server}")
            return None
        return conn

    except Exception as e:
        log.critical(f'Error logging in to {ip}')
        log.info("Trying guest session... ")

        try:
            conn = Connection(server, user='Guest', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server} as {username}")
                return None
            return conn

        except Exception as e:
            log.critical(f'Error logging in to {ip}, as {username}')
            log.info("Trying null session... ")

            conn = Connection(server, user='', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server}")
                return None
            return conn

# 2nd snaffle step, finding additional targets from original target via LDAP queries


def list_computers(connection: Connection, domain):
    dn = get_domain_dn(domain)
    if connection is None:
        log.critical("Connection is not established")
        sys.exit(2)

    try:
        connection.search(search_base=dn, search_filter='(&(objectCategory=Computer)(name=*))',
                          search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)
        domain_names = []

        for entry in connection.entries:
            sep = str(entry).strip().split(':')
            # Sometimes there's no dNSHostName
            if len(sep) == 7:
                domain_names.append(sep[6])

        return domain_names

    except Exception as e:
        log.critical(f"Unable to list computers: {e}")
        return None
