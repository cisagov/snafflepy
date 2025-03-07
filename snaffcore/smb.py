import ntpath
import struct
import logging
import termcolor

# from .errors import *
from .file_handling import *
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smbconnection import SessionError, SMBConnection


# RT: Stolen from manspider - https://github.com/blacklanternsecurity/MANSPIDER

# set up logging
log = logging.getLogger('snafflepy.smb')


class SMBClient:
    '''
    Wrapper around impacket's SMBConnection() object
    '''

    def __init__(self, server, username, password, domain, nthash, share_names):

        self.server = server

        self.conn = None

        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.share_names = share_names
        if self.nthash:
            # means no password, see https://yougottahackthat.com/blog/339/what-is-aad3b435b51404eeaad3b435b51404ee
            self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
        else:
            self.lmhash = ''

    @property
    def shares(self):

        try:
            resp = self.conn.listShares()
            for i in range(len(resp)):
                sharename = resp[i]['shi1_netname'][:-1]
                remarkname = resp[i]['shi1_remark'][:-1]
                # log.info(f'Found share {sharename} on {self.server}, remark {remarkname}')

                if(self.share_names != "" or self.share_names != None): # if shares are empty, then scan all shares
                    if(not sharename in self.share_names.split(",")): # if share is not in our list of shares to scan, skip it
                         continue

                share_text = termcolor.colored("[Share]", 'light_yellow')

                print(share_text, termcolor.colored(
                    f"{{Green}} \\\\{self.server}\\{sharename} ({remarkname})", 'green', 'on_white'))
                # log.info(f'{self.server}: Share: {sharename}')

                yield sharename

        except Exception as e:
            e = handle_impacket_error(e, self)
            log.debug(f'{self.server}: Error listing shares: {e}')

    def login(self, refresh=False, first_try=True):
        '''
        Create a new SMBConnection object (if there isn't one already or if refresh is True)
        Attempt to log in, and switch to null session if logon fails
        Return True if logon succeeded
        Return False if logon failed
        '''

        if self.conn is None or refresh:
            try:
                self.conn = SMBConnection(
                    self.server, self.server, sess_port=445, timeout=10)
            except Exception as e:
                # log.info(f"Timeout exceeded, unable to connect to {self.server}")
                e = handle_impacket_error(e, self, display=True)
                # self.conn = SMBConnection(
                #     self.server, self.server, sess_port=139, timeout=10)

            try:

                if self.username in [None, '', 'Guest'] and first_try:
                    # skip to guest / null session
                    assert False

                log.debug(
                    f'{self.server}: Authenticating as "{self.username}"')

                # pass the hash if requested
                if self.nthash and not self.password:
                    self.conn.login(
                        self.username,
                        '',
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        domain=self.domain,
                    )
                # otherwise, normal login
                else:
                    self.conn.login(
                        self.username,
                        self.password,
                        domain=self.domain,
                    )

                log.debug(
                    f'{self.server}: Successful login as "{self.username}"')
                return True

            except Exception as e:

                if type(e) != AssertionError:
                    e = handle_impacket_error(e, self, display=False)

                # try guest account, then null session if logon failed
                if first_try:

                    bad_statuses = [
                        'LOGON_FAIL', 'PASSWORD_EXPIRED', 'LOCKED_OUT', 'SESSION_DELETED']
                    if any([s in str(e) for s in bad_statuses]):
                        for s in bad_statuses:
                            if s in str(e):
                                log.warning(
                                    f'{self.server}: {s}: {self.username}')

                    log.debug(f'{self.server}: Trying guest session')
                    self.username = 'Guest'
                    self.password = ''
                    self.domain = ''
                    self.nthash = ''
                    guest_success = self.login(refresh=True, first_try=False)
                    if not guest_success:
                        log.debug(f'{self.server}: Switching to null session')
                        self.username = ''
                        self.login(refresh=True, first_try=False)

            return False

        else:
            return True

    def ls(self, share, path):
        '''
        List files in share/path
        Raise FileListError if there's a problem
        @byt3bl33d3r it's really not that bad
        '''

        nt_path = ntpath.normpath(f'{path}\\*')

        # for every file/dir in "path"
        try:
            for f in self.conn.listPath(share, nt_path):
                # exclude current and parent directory
                if f.get_longname() not in ['', '.', '..']:
                    yield f
        except Exception as e:
            e = handle_impacket_error(e, self)
            raise FileListError(
                f'{e.args}: Error listing files at "{share}{nt_path}"')

    def rebuild(self, error=''):
        '''
        Rebuild our SMBConnection() if it gets borked
        '''

        log.debug(
            f'Rebuilding connection to {self.server} after error: {error}')
        self.login(refresh=True)

    # Handle download errors and recurse into directories, current implementation may not work properly
    # I think there needs to be a finally block that goes through the current directory and tries to get any remaining files/dirs because
    # it will stop as soon as it finds one subdirectory
    # def handle_download_error(self, share, dir_path, err, isFromGoLoud:bool):
    #     add_err = False
    #     problem_files = []

    #     if str(err).find("STATUS_FILE_IS_A_DIRECTORY"):
    #         dir_text = termcolor.colored("[Directory]", 'light_blue')

    #         if isFromGoLoud:
    #             log.info(f"{dir_text}\\\\{self.server}\\{share}\\{dir_path}")

    #         subfiles = self.ls(share, str(dir_path))

    #         for subfile in subfiles:
    #             sub_size = subfile.get_filesize()
    #             sub_name = str(dir_path + "\\" + subfile.get_longname())

    #             # try:
    #             subfile = RemoteFile(sub_name, share, self.server, sub_size)
    #             subfile.get(self)

    #             if FileRetrievalError:
    #                 add_Err = True
    #                 problem_files.append(subfile)
    #                 continue
    #             else:
    #                 file_text = termcolor.colored("[File]", 'green')
    #                 if isFromGoLoud:
    #                     log.info(f"{file_text} \\\\{self.server}\\{share}\\{sub_name}")

    #             # except FileRetrievalError as e:
    #             if str(err).find("STATUS_FILE_IS_A_DIRECTORY"):
    #                 dir_text = termcolor.colored("[Directory]", 'light_blue')

    #                 if isFromGoLoud:
    #                     log.info(f"{dir_text}\\\\{self.server}\\{share}\\{sub_name}")
    #                     self.handle_download_error(share, sub_name, e, True)

    #                 else:
    #                     self.handle_download_error(share, sub_name, e, False)

    #             elif str(err).find("ACCESS_DENIED"):
    #                 continue

        # ORIGINAL
        # if str(err).find("STATUS_FILE_IS_A_DIRECTORY"):
        #     dir_text = termcolor.colored("[Directory]", 'light_blue')
        #     if isFromGoLoud:
        #         log.info(f"{dir_text}\\\\{self.server}\\{share}\\{dir_path}")
        #     try:
        #         subfiles = self.ls(share, str(dir_path))

        #     except FileListError as e:
        #         log.error(f"Access denied, cannot read at \\\\{self.server}\\{share}\\{dir_path}")

        #     for subfile in subfiles:

        #         sub_size = subfile.get_filesize()
        #         sub_name = str(dir_path + "\\" + subfile.get_longname())

        #         try:
        #             subfile = RemoteFile(sub_name, share, self.server, sub_size)
        #             subfile.get(self)

        #             file_text = termcolor.colored("[File]", 'green')
        #             if isFromGoLoud:
        #                 log.info(f"{file_text} \\\\{self.server}\\{share}\\{sub_name}")

        #             # self.handle_download_error(share, sub_name, err)
        #         except Exception as e:
        #             if str(err).find("STATUS_FILE_IS_A_DIRECTORY"):
        #                 dir_text = termcolor.colored("[Directory]", 'light_blue')

        #                 if isFromGoLoud:
        #                     log.info(f"{dir_text}\\\\{self.server}\\{share}\\{sub_name}")
        #                     self.handle_download_error(share, sub_name, e, True)

        #                 else:
        #                     self.handle_download_error(share, sub_name, e, False)

        #             elif str(err).find("ACCESS_DENIED"):
        #                 continue
