# Linux: scheduled discovery upload

Run as each user whose home should be scanned (the scanner reads that user's home folder).

1. Install Shield for the user (see `docs/msp-zero-touch.md`).
2. As root, write the key where the user can read it but nobody else can change it:

   ```bash
   install -d -m 755 /etc/coriqo/shield
   ( umask 022; printf '{"key":"%s","server_url":"%s"}' "$DISCOVERY_KEY" "https://coriqo.example.com" \
       > /etc/coriqo/shield/discover.json )
   chown root:root /etc/coriqo/shield/discover.json && chmod 644 /etc/coriqo/shield/discover.json
   ```

   The command refuses the file if it is writable by group or other or owned by someone else.
3. Schedule it as the user (`crontab -e`). Quiet when Shield is absent, spread out by up to 10 minutes:

   ```cron
   17 9 * * * [ -x "$HOME/.byoai/venv/bin/byoai-shield" ] && "$HOME/.byoai/venv/bin/byoai-shield" discover --send --jitter-seconds 600 >/dev/null 2>&1
   ```

   A systemd user timer works the same way. Exit codes are in `CONFIGURATION.md`; run the command by hand once
   to see the one-line reason if it fails.

The key never goes on the command line. Rotate it in Coriqo (Settings, Endpoint discovery) and rewrite the file.
