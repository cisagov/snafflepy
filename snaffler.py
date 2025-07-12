import argparse
import sys
import logging
import os

from snaffcore.go_snaffle import *
from snaffcore.utilities import *
from snaffcore.logger import *

log = logging.getLogger('snafflepy')
log.setLevel(logging.INFO)


def parse_arguments():
    syntax_error = False
    print("SnafflePy by @robert-todora")

    parser = argparse.ArgumentParser(
        add_help=True, prog='snaffler.py', description='A "port" of Snaffler in python')
    parser.add_argument("targets", nargs='+', type=make_targets,
                        help="IPs, hostnames, CIDR ranges, or files contains targets to snaffle. If you are providing more than one target, the -n option must be used.")
    parser.add_argument("-u", "--username",
                        type=str, help="domain username")
    parser.add_argument("-p", "--password",
                        type=str, help="password for domain user")
    parser.add_argument("-d", "--domain",
                        default="", help="FQDN domain to authenticate to, if this option is not provided, SnafflePy will attempt to automatically discover the domain for you")
    parser.add_argument("-H", "--hash",
                        default="", help="NT hash for authentication")
    parser.add_argument("-v", "--verbose",
                        action='store_true', help="Show more info")
    parser.add_argument("--go-loud", action='store_true',
                        help="Don't try to find anything interesting, literally just go through every computer and every share and print out as many files as possible. Use at your own risk")
    
    parser.add_argument("-m", "--max-file-snaffle", metavar="size", type=int, default=10000, help="Max filesize to snaffle in bytes (any files over this size will be dropped)")
    # TODO
    # parser.add_argument("-i", "--no-share-discovery", action='store_true',
    #                    help="Disables share discovery (more stealthy)")
    parser.add_argument("-n", "--disable-computer-discovery", action='store_true',
                        help="Disable computer discovery, requires a list of hosts to do discovery on")
    
    parser.add_argument("--no-download", action='store_true', help="Don't download files, just print found file names to stdout - this can only show the top level of files from the share and is unable to recurse into subdirectories.")

    parser.add_argument("-s", "--shares", action="store_true", help="Comma separated list of shares to scan. ie: hr,document,test")

    try:
        if len(sys.argv) <= 1:
            parser.print_help()
            sys.exit(1)

    except argparse.ArgumentError as e:
        syntax_error = True
        log.error(e)
        log.error('Check your syntax')

    finally:
        if syntax_error:
            parser.print_help()
            sys.exit(2)
        else:
            options = parser.parse_args()
            if options.verbose:
                log.setLevel('DEBUG')

            targets = set()
            [[targets.add(t) for t in g] for g in options.targets]
            options.targets = list(targets)

            if len(options.targets) > 1 and not options.disable_computer_discovery:
                log.error("If you have more than one target, then the -n option must be specified.")
                sys.exit(2)
            return options


def print_banner():
    print(r'''  
  O~~ ~~                         O~~    O~~ O~~          O~~~~~~~           
O~~    O~~                     O~     O~    O~~          O~~    O~~         
 O~~      O~~ O~~     O~~    O~O~ O~O~O~ O~ O~~   O~~    O~~    O~~O~~   O~~
   O~~     O~~  O~~ O~~  O~~   O~~    O~~   O~~ O~   O~~ O~~~~~~~   O~~ O~~ 
      O~~  O~~  O~~O~~   O~~   O~~    O~~   O~~O~~~~~ O~~O~~          O~~~  
O~~    O~~ O~~  O~~O~~   O~~   O~~    O~~   O~~O~        O~~           O~~  
  O~~ ~~  O~~~  O~~  O~~ O~~~  O~~    O~~  O~~~  O~~~~   O~~          O~~   
                                                                    O~~     ''')

    print("")
    print("")


def main():
    print_banner()
    snaffle_options = parse_arguments()
    begin_snaffle(snaffle_options)

    print("\nI snaffled 'til the snafflin was done")
    print("View log file at ~/.snafflepy/logs/")
    print("Files snaffled from targets are available in <PATH-TO-SNAFFLEPY>/remotefiles/")
    sys.exit()


if __name__ == '__main__':
    main()
