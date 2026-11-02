#!/usr/bin/env bash
#
# Set up a throwaway, self-contained Samba server on 127.0.0.1 for integration
# testing SnafflePy. Everything (config, state, seeded files) lives under one
# lab directory, so nothing touches your system Samba configuration.
#
# Guest access is enabled, so no Samba user/password setup is required -
# SnafflePy will connect via its guest/null-session fallback.
#
# Usage:
#   tests/integration/setup_smb_lab.sh [LAB_DIR]      # seed files + write config
#   sudo smbd -F -s <LAB_DIR>/smb.conf --no-process-group   # run it (needs root for port 445)
#
# Then, in another terminal:
#   python3 snaffler.py 127.0.0.1 -d WORKGROUP -n -u Guest -p '' -v
#
set -euo pipefail

LAB_DIR="${1:-/tmp/snafflepy-smblab}"
SHARE_DIR="$LAB_DIR/share"
CONF="$LAB_DIR/smb.conf"

echo "[*] Building Samba lab in: $LAB_DIR"
# A previous `sudo smbd` run leaves root-owned state here, which this script
# (running as a normal user) can't delete. Detect that and give clear advice
# instead of aborting half-way through.
if [ -e "$LAB_DIR" ]; then
    if ! rm -rf "$LAB_DIR" 2>/dev/null || [ -e "$LAB_DIR" ]; then
        echo "[!] Could not fully remove $LAB_DIR (root-owned files from a prior smbd run)." >&2
        echo "    Run:  sudo rm -rf $LAB_DIR" >&2
        echo "    then re-run this script." >&2
        exit 1
    fi
fi
mkdir -p "$SHARE_DIR" \
         "$LAB_DIR/private" "$LAB_DIR/lock" "$LAB_DIR/state" \
         "$LAB_DIR/cache" "$LAB_DIR/run" "$LAB_DIR/log" "$LAB_DIR/ncalrpc"
# Samba expects 0755 on its state dirs for browsing to work.
chmod 0755 "$LAB_DIR/lock" "$LAB_DIR/state" "$LAB_DIR/cache"

# ---------------------------------------------------------------------------
# Seed files: a mix of things that SHOULD match rules and noise that shouldn't.
# ---------------------------------------------------------------------------
mkdir -p "$SHARE_DIR/Users/bob/.ssh" \
         "$SHARE_DIR/Users/bob/Documents" \
         "$SHARE_DIR/Windows/system32" \
         "$SHARE_DIR/app/node_modules" \
         "$SHARE_DIR/deploy"

# --- should be SNAFFLED (name/extension/path rules) ---
cat > "$SHARE_DIR/Users/bob/.ssh/id_rsa" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA (fake test key)
-----END OPENSSH PRIVATE KEY-----
EOF
printf 'PuTTY-User-Key-File-2: ssh-rsa\n' > "$SHARE_DIR/deploy/server.ppk"
printf 'admin:$apr1$abc$def\n' > "$SHARE_DIR/.htpasswd"

# --- should be RELAYED then CONTENT-matched ---
cat > "$SHARE_DIR/app/web.config" <<'EOF'
<configuration>
  <connectionStrings>
    <add name="db" connectionString="Server=x;User Id=sa;password=Sup3rSecret!" />
  </connectionStrings>
</configuration>
EOF
cat > "$SHARE_DIR/deploy/notes.txt" <<'EOF'
reminder: the service account api_key = "AKIAIOSFODNN7EXAMPLE1234"
password = "hunter2hunter2"
EOF

# --- should be CheckForKeys ---
cat > "$SHARE_DIR/deploy/cert.pem" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA (fake test material, not a real key)
-----END RSA PRIVATE KEY-----
EOF

# --- noise that should be DISCARDED / ignored ---
echo "not interesting" > "$SHARE_DIR/Users/bob/Documents/photo.jpg"
echo "binary-ish noise" > "$SHARE_DIR/app/node_modules/index.js"
echo "system file"       > "$SHARE_DIR/Windows/system32/kernel32.dll"
echo "just a readme"     > "$SHARE_DIR/Users/bob/Documents/readme.md"

# ---------------------------------------------------------------------------
# Minimal, self-contained smb.conf bound to loopback only.
# ---------------------------------------------------------------------------
cat > "$CONF" <<EOF
[global]
    workgroup = WORKGROUP
    server string = snafflepy-lab
    security = user
    map to guest = Bad User
    guest account = nobody
    smb ports = 445
    interfaces = 127.0.0.1
    bind interfaces only = yes
    disable netbios = yes
    log level = 1

    private dir = $LAB_DIR/private
    lock directory = $LAB_DIR/lock
    state directory = $LAB_DIR/state
    cache directory = $LAB_DIR/cache
    pid directory = $LAB_DIR/run
    ncalrpc dir = $LAB_DIR/ncalrpc
    log file = $LAB_DIR/log/smbd.log

[testshare]
    path = $SHARE_DIR
    browseable = yes
    read only = yes
    guest ok = yes
    guest only = yes
EOF

echo "[+] Lab ready."
echo
echo "    Share contents:"
find "$SHARE_DIR" -type f | sed "s|^|      |"
echo
echo "[*] Start the server (needs root to bind port 445):"
echo "      sudo smbd -F -s $CONF --no-process-group"
echo
echo "[*] Verify it is up (in another terminal):"
echo "      smbclient -N -L //127.0.0.1"
echo "      smbclient -N //127.0.0.1/testshare -c 'recurse; ls'"
echo
echo "[*] Run SnafflePy against it:"
echo "      python3 snaffler.py 127.0.0.1 -d WORKGROUP -n -u Guest -p '' -v"
echo "      # or scan only the test share:"
echo "      python3 snaffler.py 127.0.0.1 -d WORKGROUP -n -u Guest -p '' -s testshare"
