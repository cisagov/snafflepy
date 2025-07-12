import sys

from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE
# from .smb import * 
from .utilities import *
# from .file_handling import *
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
            log.error(f"Unable to login to{target}")
            continue
        
        for share in smb_client.shares:
            files = []
            try:
                if not options.go_loud:
                    if is_interest_share(share, snaff_rules) == False:
                        log.debug(f"{share} matched a Discard rule, skipping files inside of this share...")
                        continue
                    
                files = smb_client.ls(share, "")

            
            
                for file in files:
                    size = file.get_filesize()
                    name = file.get_longname()
                    # bad_name = name
                    file = RemoteFile(name, share, target, size, smb_client)

                    if options.go_loud:
                        try:
                            file_text = termcolor.colored("[File]", 'green')
                            if not options.no_download:
                                file.get(smb_client)
                            log.info(
                                f"{file_text} \\\\{target}\\{share}\\{name}")

                        except FileRetrievalError as e:
                            no_add_error = False
                            keep_dir_name = True
                            # Check if its a directory, and try to list files/more directories here
                            file.handle_download_error(
                                file.name, e, options.go_loud, no_add_error)
                            
                    else:
                        if size >= options.max_file_snaffle:
                            pass
                        else:
                            try:
                                is_interest_file(file, smb_client, share, options.no_download)
                            except FileRetrievalError as e:
                                # Error will trigger if access denied to file, or the file is actually a directory
                                # File 
                                # keep_dir_name = classify_directory(file.name, snaff_rules)
                                no_add_error = False
                                file.handle_download_error(
                                    file.name, e, options.go_loud, no_add_error)
                                
            except FileListError as e:
                log.error(f"Cannot list files at {share} {e}")
    
                
           

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
