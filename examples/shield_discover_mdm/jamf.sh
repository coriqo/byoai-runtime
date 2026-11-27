#!/bin/bash
# Jamf Pro policy script: upload this Mac's `byoai-shield discover` report to Coriqo.
# Runs as root; $3 is the signed-in user, $4 the discovery key (a secret Jamf script parameter).
# Schedule the policy "Ongoing", once per day. The scanner reads the user's home, so it runs as the user.
USER_NAME="$3"
KEY="$4"
SERVER="https://coriqo.example.com"   # placeholder: your Coriqo address
BIN="/Users/$USER_NAME/.byoai/venv/bin/byoai-shield"

[ -x "$BIN" ] || exit 0               # Shield not installed here: nothing to do, stay quiet
[ -n "$USER_NAME" ] && [ "$USER_NAME" != "root" ] || exit 0   # nobody signed in
[ -n "$KEY" ] || { echo "no discovery key set"; exit 1; }

DIR="/Library/Application Support/Coriqo/Shield"
mkdir -p "$DIR"
umask 022
# The key lives in a root-owned file the user can read, never on the command line.
( umask 077; printf '{"key":"%s","server_url":"%s"}' "$KEY" "$SERVER" > "$DIR/discover.json" )
chown root:wheel "$DIR/discover.json"
chmod 644 "$DIR/discover.json"        # root-owned, not writable by group or other, as the command requires

sudo -u "$USER_NAME" -H "$BIN" discover --send --jitter-seconds 600 >/dev/null
exit $?
