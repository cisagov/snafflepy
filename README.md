# SnafflePy
Snaffler reimplementation in Python - https://github.com/SnaffCon/Snaffler 
This tool works by first sending a LDAP query to the specified target to discover other domain joined machines, and then attempts to login (authenticated or not) through SMB and retrieve interesting files. 

### Current Features: 
SnafflePy includes different options and methods of enumeration. It can discover AD joined computers automatically by performing specific LDAP queries to Active Directory and include them in its target list, or if you want to disable this, it can also manually take in a list of IPs, hostnames, or CIDR ranges as its targets. It can also return every share and filename that is readable on the target network, authenticated or unauthenticated. If the credentials provided fail, then SnafflePy will automatically attempt to login via a Guest user, and if that fails it will attempt to login via a “NULL” session. It also supports the original TOML rule formats from Snaffler and uses them to identify interesting file and share names that are returned to the user. 

### Features to Add: 
1. Make it way faster
2. Output to JSON

## Use case:

Sometimes you do not always have access to a domain joined windows machine when you want to Snaffle. With this tool, you can "snaffle" from a non windows machine!  

## Installation (Linux):

1. Clone this repository

2. Optional but encouraged, create a virtual environment for this project
3. `python -m venv venv`
4. `source venv/bin/activate`
5. `pip install -r requirements.txt` 

## Usage and Options
~~~
SnafflePy by @robert-todora
usage: snaffler.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-v] [--go-loud] [-m size] [-n] [--no-download] targets [targets ...]

A "port" of Snaffler in python

positional arguments:
  targets               IPs, hostnames, CIDR ranges, or files contains targets to snaffle. If you are providing more than one target, the -n option must be used.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        domain username
  -p PASSWORD, --password PASSWORD
                        password for domain user
  -d DOMAIN, --domain DOMAIN
                        FQDN domain to authenticate to, if this option is not provided, SnafflePy will attempt to automatically discover the domain for you
  -H HASH, --hash HASH  NT hash for authentication
  -v, --verbose         Show more info
  --go-loud             Don't try to find anything interesting, literally just go through every computer and every share and print out as many files as possible. Use at your own risk
  -m size, --max-file-snaffle size
                        Max filesize to snaffle in bytes (any files over this size will be dropped)
  -n, --disable-computer-discovery
                        Disable computer discovery, requires a list of hosts to do discovery on
  --no-download         Don't download any files. Shares, directories (recursively), and file name/extension/path rules are still evaluated and printed; only content-based checks (which require reading the file) are skipped.
  -s SHARES, --shares SHARES
                        Comma separated list of shares to scan. ie: hr,document,test
  --unc UNC_PATH        Optional UNC path to a specific share. ie: \\192.168.1.1\hr

~~~

## Examples

1. Automatically discover the domain name and identify shares and find interesting files from them  

`python3 snaffler.py <IP> -u <username> -p <password> -v`

2. Scan specific shares across a target range

`python3 snaffler.py <IP> -u <username> -p <password> -s hr,documents -n`

3. Scan a specific UNC path directly

`python3 snaffler.py --unc \\\\<IP>\\hr -u <username> -p <password>`

5. Authenticate with an NT hash instead of a password (pass-the-hash), which is used for both the SMB and LDAP connections

`python3 snaffler.py <IP> -u <username> -H <nthash> -d <domain>`

6. Leave off the password and SnafflePy will prompt you for it, press enter at the prompt to use a blank password

`python3 snaffler.py <IP> -u <username> -d <domain>`

7. Identify interesting shares, directories, and files by name without downloading anything, content-based checks are skipped

`python3 snaffler.py <IP> -u <username> -p <password> --no-download`

8. Raise the maximum file size in bytes so larger files are still downloaded and scanned for secrets in their contents

`python3 snaffler.py <IP> -u <username> -p <password> -m 500000`

## Output

<img width="1272" height="577" alt="Screenshot 2026-11-08 123442" src="https://github.com/user-attachments/assets/7fa8c6f2-589d-4fe6-ab30-cb4d81658666" />


Thank you to MANSPIDER for the helpful code: https://github.com/blacklanternsecurity/MANSPIDER

Tested with Python 3.14.7

## Author Information
Robert Todora - robert.todora@cisa.dhs.gov (Note: no longer active)

## AI Disclaimer
Since development work on this project became active again in 2026, AI has been used to help with bug fixes, adding new features, and writing test cases.
