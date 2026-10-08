import argparse
import sys
import logging
import os

from snaffcore.go_snaffle import *
from snaffcore.utilities import *
from snaffcore.logger import *

log = logging.getLogger('snafflepy')
log.setLevel(logging.INFO)

def parse_unc_path(value):
    """Validate and parse UNC path in \\\\server\\share format, storing each part separately."""
    if not value.startswith("\\\\"):
        raise argparse.ArgumentTypeError(f"UNC path must start with \\\\, got: {value}")
    parts = value.lstrip("\\").split("\\")
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(f"UNC path must be in format \\\\server\\share, got: {value}")
    return {"target": parts[0], "share": parts[1]}


def parse_arguments():
    syntax_error = False
    print("SnafflePy by @robert-todora")

    parser = argparse.ArgumentParser(
        add_help=True, prog='snaffler.py', description='A "port" of Snaffler in python')
    parser.add_argument("targets", nargs='*', type=make_targets,
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

    parser.add_argument("-s", "--shares", action="store", help="Comma separated list of shares to scan. ie: hr,document,test")

    parser.add_argument("--unc", type=parse_unc_path,metavar="UNC_PATH", help=r"Optional UNC path to a specific share. ie: \\\\192.168.1.1\\hr")

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
            shares = set()
            if options.unc:
                targets.add(options.unc["target"])
                shares.add(options.unc["share"])
            if options.targets:
                [[targets.add(t) for t in g] for g in options.targets]
            if options.shares:
                [shares.add(s.strip()) for s in options.shares.split(",") if s.strip()]
            if not targets:
                log.error("No targets specified. Provide at least one target or a --unc path.")
                parser.print_help()
                sys.exit(2)
            options.targets = list(targets)
            options.shares = list(shares) if shares else None
            if len(options.targets) > 1 and not options.disable_computer_discovery:
                log.error("If you are have more than one target, then the -n option must be specified.")
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
