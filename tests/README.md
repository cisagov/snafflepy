# Testing SnafflePy

Two tiers of tests:

| Tier | What it checks | Needs network? | Needs root? |
|------|----------------|----------------|-------------|
| Unit (`test_classifier.py`) | The TOML rule engine: share/dir/file/content classification, Relay, CheckForKeys, PostMatch | No | No |
| Integration (`integration/`) | The real SMB crawl against a live Samba share | Loopback only | Yes (to bind port 445) |

## 1. One-time environment setup

Use a virtualenv so dependencies stay off the system Python:

```bash
python3 -m venv .snafflepy-venv
source .snafflepy-venv/bin/activate
pip install -r requirements.txt pytest
```

> On Python 3.11+ the classifier uses the stdlib `tomllib`, so the `toml`
> package is only needed on older interpreters.

## 2. Unit tests (fast, run these constantly)

```bash
pytest tests/test_classifier.py -v
```

These load the real `snaffcore/DefaultRules/` ruleset and assert on
classification outcomes using in-memory fake files — no SMB server involved.
Add a case whenever you add or change a rule behavior.

## 3. Integration tests (real SMB crawl)

A throwaway Samba server, bound to `127.0.0.1` only, seeded with files that
should and shouldn't match. Everything lives under one lab directory; your
system Samba config is untouched. Guest access is enabled, so no Samba user
setup is needed.

**Terminal 1 — build the lab and start the server:**

```bash
tests/integration/setup_smb_lab.sh                     # seeds /tmp/snafflepy-smblab
sudo smbd -F -s /tmp/snafflepy-smblab/smb.conf --no-process-group
```

(Root is only needed because SMB uses privileged port 445, which SnafflePy
connects to directly. `-F` keeps the master process running and forks a child
per connection — don't use `-i`/interactive, which services one connection and
then exits. Add `--debug-stdout` to see activity live, or tail the log:
`tail -f /tmp/snafflepy-smblab/log/smbd.log`.)

**Terminal 2 — confirm the share is reachable, then run SnafflePy:**

```bash
smbclient -N -L //127.0.0.1                            # should list "testshare"
python3 snaffler.py 127.0.0.1 -d WORKGROUP -n -u Guest -p '' -v
```

Two flags matter for standalone (non-domain) testing:
- `-d WORKGROUP` skips automatic LDAP domain discovery (there's no DC).
- `-n` disables computer discovery (no LDAP lookup of other hosts).

### What to expect

Against the seeded share, SnafflePy should:

- **Snaffle** `id_rsa`, `server.ppk`, `.htpasswd`
- **Relay → content-match** `web.config` and `notes.txt` (password / api key)
- **Relay → SSN match** `hr_export.csv` (contains US SSNs)
- **CheckForKeys** flag `cert.pem` (contains a private-key marker)
- **Discard / ignore** `photo.jpg`, `readme.md`, and everything under
  `Windows\system32\` and `app\node_modules\` (path Discard rules)

Downloaded copies land in `remotefiles/127.0.0.1/testshare/...`.

### Teardown

```bash
# Ctrl-C the smbd in terminal 1, then:
sudo rm -rf /tmp/snafflepy-smblab    # smbd runs as root, so its state is root-owned
rm -rf remotefiles
```

## Notes / gotchas

- If `smbd` complains that port 445 is in use, stop the system Samba first:
  `sudo systemctl stop smbd` (or kill the running `smbd`).
- The seeded "keys" are non-functional placeholder text, safe to commit nowhere
  and safe to scan.
- The crawl connects to port 445 only (hardcoded in `snaffcore/smb.py`); there
  is no 139 fallback.
