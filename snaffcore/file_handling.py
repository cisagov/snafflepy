from .utilities import *
from .errors import *

from pathlib import Path
import os
import re
import termcolor


# RT: Stolen from manspider - https://github.com/blacklanternsecurity/MANSPIDER


def _sanitize(part):
    '''Strip characters that are unsafe or illegal in a local filename.'''
    part = re.sub(r'[<>:"|?*\x00-\x1f]', '_', part)
    return part.strip() or '_'


class RemoteFile():
    '''
    Represents a file on an SMB share
    Passed from a spiderling up to its parent spider    
    '''

    def __init__(self, name, share, target, size=0, smb_client=None):

        self.share = share
        self.target = target
        self.name = name
        self.size = size
        self.smb_client = smb_client

        # Build a safe local destination under ./remotefiles that mirrors the
        # remote layout. The remote name can contain Windows path separators
        # (e.g. "dir\\sub\\file.txt") when recursing into subdirectories, so we
        # split on them and rebuild with the local OS separator. This keeps
        # files from different directories from clobbering each other.
        # NOTE: the directory is only created lazily in get(), so simply
        # constructing a RemoteFile (e.g. in --no-download mode, or for files
        # that get discarded) never touches the filesystem.
        safe_parts = [p for p in re.split(r'[\\/]+', str(self.name)) if p not in ('', '.', '..')]
        self.tmp_filename = Path('remotefiles').joinpath(
            _sanitize(str(self.target)), _sanitize(str(self.share)),
            *[_sanitize(p) for p in safe_parts])

    def get(self, smb_client=None):
        '''
        Downloads file to self.tmp_filename

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        '''

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError('Please specify smb_client')

        # Create the destination directory tree only now, when we actually
        # have a file to write.
        self.tmp_filename.parent.mkdir(parents=True, exist_ok=True)

        # memfile = io.BytesIO()
        with open(str(self.tmp_filename), 'wb') as f:

            try:
                smb_client.conn.getFile(self.share, self.name, f.write)
            except Exception as e:
                handle_impacket_error(e, smb_client, self.share, self.name)
                raise FileRetrievalError(
                    f'Error retrieving file "{str(self)}": {str(e)[:150]}')

        # reset cursor back to zero so .read() will return the whole file
        # memfile.seek(0)

    def __str__(self):

        return f'\\\\{self.target}\\{self.share}\\{self.name}'

    def handle_download_error(self, dir_path, err, is_from_go_loud: bool, add_err: bool):
        # subfiles = []
        if "DIRECTORY" in str(err):
            dir_text = termcolor.colored("[Directory]", 'light_blue')

            if is_from_go_loud:
                log.info(
                    f"{dir_text} \\\\{self.target}\\{self.share}\\{dir_path}")
            try:
                subfiles = self.smb_client.ls(self.share, str(dir_path))
                add_err = False
            

                for subfile in subfiles:
                    sub_size = subfile.get_filesize()
                    sub_name = str(dir_path + "\\" + subfile.get_longname())

                    try:
                        subfile = RemoteFile(
                            sub_name, self.share, self.target, sub_size)
                        if is_from_go_loud:
                            subfile.get(self.smb_client)
                        # else: 
                            # is_interest_file(self, self.smb_client, self.share)
                        add_err = False

                    except FileRetrievalError as e:
                        # handle_impacket_error(e, subfile.smb_client, subfile.share, sub_name, True)
                        err = e
                        add_err = True

                    finally:
                        if add_err:
                            # print(error)
                            self.handle_download_error(
                                sub_name, err, is_from_go_loud, True)
                        else:
                            file_text = termcolor.colored("[File]", 'green')
                            if is_from_go_loud:
                                log.info(
                                    f"{file_text} \\\\{self.target}\\{self.share}\\{sub_name}")
            except FileListError as e:
                if is_from_go_loud:
                    log.error(
                        f"Access denied, cannot read at {self.target}\\{self.share}\\{dir_path}")
