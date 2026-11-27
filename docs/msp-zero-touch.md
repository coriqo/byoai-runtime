# Zero-touch Shield deployment (MDM)

Goal: an administrator sets up Shield on many managed computers with two steps
and no per-machine clicks.

1. Create one enrolment key for each client in the Coriqo MSP console.
2. Push one script from your device-management tool (Jamf, Intune, Kandji, a
   Windows startup script). It places the key and the server address on the
   computer and runs `byoai-shield enrol`.

This page says plainly what works today and what does not. It is not yet "one
push, nothing else": Shield and the browser extension still need their own
install step (see "What exists today").

!!! note "Release status"
    The reusable per-client key is merged in Coriqo but ships with Coriqo's
    next release. An older Coriqo only has single-use tokens, one per
    computer: use "Fallback: single-use tokens" below. Nothing in this repo
    changes between the two; the command takes either.

## What exists today

| Piece | Status |
|---|---|
| `byoai-shield enrol` reads the key or token and the server address from a managed registry key, macOS managed preference or root-owned file | Built (this repo) |
| `byoai-shield enrol` accepts a reusable client key in the same place as a single-use token (`EnrolToken`, `--token`, `--token-file`), with random start delay and retry of a busy server | Built (this repo). Nothing in the command is specific to the key |
| One reusable enrolment key per client, with a device limit, an end date, a second person's approval, revoke and an audit record per enrolment | Built in Coriqo, merged, ships with Coriqo's next release. Not in this repo |
| One server address for all devices, shown on the client's Enrol tab | Built in Coriqo, same release |
| Extension reads `shield_port` and `managed_by` from managed storage (`managed_schema.json`); the port is then not changeable by the person | Built (this repo), ships in the next extension release |
| Extension force-install by Chrome policy | Works with any extension id. The Chrome Web Store listing is not published, so there is no store id to put in the policy (see "Where the extension comes from") |
| Shield install on many computers | Not built. Today it is `pip install` per computer and needs Python. A signed `.pkg` (macOS) and `.msi` (Windows) are missing |
| Creating many clients at once, and exporting their keys as a CSV | Not built. Each client is created in the console and its key is created one client at a time |
| Licence metering of enrolled devices | Partly built in Coriqo: a billing sync sets the quantity for the clients an MSP owns. The full device meter in the billing spec is not built. Enrolment is never blocked by the licence |
| Trusting Shield's capture proxy (CA certificate, proxy settings) by profile | Not built. The browser-extension route below needs neither |
| A live run of this page on a real Jamf or Intune tenant | Not done. The scripts below follow the command's documented inputs and have not been run on a managed fleet |

So the honest demo today is: a policy-installed extension, a scripted Shield
install per computer, and a key per client. Rolling out to a thousand
customers in two steps is not possible yet: the missing pieces are bulk client
creation, the signed installers, a published extension id and a run on a real
MDM.

## Step 1: create the client's key

In the MSP console, open the client, then the **Enrol** tab, then **Enrol the
whole client**.

1. Copy the server address shown on the Enrol tab. It is one public address for
   the whole deployment. Devices use it as `ServerUrl`.
2. Name the key (for example "Acme head office laptops"). **Valid for**
   defaults to 7 days (at most 30). **Device limit** defaults to 25.
   Your Coriqo administrator can change these defaults.
3. Press **Request release**. A second person with the approver role approves
   it in Trust center, External releases. You cannot approve your own request.
4. Press **Send now**. The key is shown once. Copy it into your MDM secret
   store before you leave the page: Coriqo keeps only a hash and cannot show it
   again.

The key looks like `cik_key_<client>.<secret>`. It goes in the same field a
single-use token used.

Check one computer by hand first:

```sh
byoai-shield enrol --server https://shield.example.com --token-file ./key.txt
```

Exit 0 means enrolled (or already enrolled). The command prints the tenant and
device, never the key. Exit 1 means the server refused or could not be
reached; exit 2 means missing or untrusted input, and the message says what to
set.

## Step 2: the push

Run as the signed-in user, not root: the device key lives in that user's
`~/.byoai/shield`. Every user on a computer who runs Shield is a separate
device and uses one place of the device limit.

Add `--jitter-seconds 120` so many computers do not arrive in the same second.

### macOS, Jamf Pro

Policy script (runs as root; `$3` is the signed-in user). Store the key as a
Jamf script parameter marked secret, or in your secrets tool. `$4` below is that
parameter.

```sh
#!/bin/bash
USER_NAME="$3"
KEY="$4"                      # the client's key, from the MDM secret store
SERVER="https://shield.example.com"   # placeholder: the address from the Enrol tab
[ -z "$KEY" ] && { echo "no enrolment key set"; exit 1; }
DIR="/Library/Application Support/Coriqo/Shield"
mkdir -p "$DIR"
umask 077
printf '{"token":"%s","server_url":"%s"}' "$KEY" "$SERVER" > "$DIR/enrol.json"
chown root:wheel "$DIR/enrol.json"
chmod 644 "$DIR/enrol.json"   # the signed-in user must read it; root-owned and not writable by group or other, as enrol requires
sudo -u "$USER_NAME" -H /Users/"$USER_NAME"/.byoai/venv/bin/byoai-shield enrol --jitter-seconds 120
STATUS=$?
sudo -u "$USER_NAME" -H /Users/"$USER_NAME"/.byoai/venv/bin/byoai-shield --install-login-item
rm -f "$DIR/enrol.json"       # nothing left on disk once enrolled
exit $STATUS
```

Shield install before that, per user, until a signed `.pkg` exists:

```sh
sudo -u "$USER_NAME" -H python3 -m venv /Users/"$USER_NAME"/.byoai/venv
sudo -u "$USER_NAME" -H /Users/"$USER_NAME"/.byoai/venv/bin/pip install --pre "byoai-runtime[shield]"
```

Instead of a file you can set a managed preference: a Jamf configuration
profile with a custom-settings payload, preference domain `com.coriqo.shield`,
keys `EnrolToken` and `ServerUrl`. macOS writes it to
`/Library/Managed Preferences/com.coriqo.shield.plist`, which the command reads.
With a reusable key this fits well: one profile scoped to one client's
computers carries the same key and address for all of them. The key then sits
in the profile for as long as the profile does; remove the profile after the
rollout, or let the key expire.

### Windows, Intune (PowerShell script or Win32 app)

The registry route is the hardened one: only administrators can write `HKLM`,
so the command trusts it.

```powershell
$key = '<CLIENT_ENROLMENT_KEY>'            # from your secret store, not typed into the script
$server = 'https://shield.example.com'     # placeholder: the address from the Enrol tab
$k = 'HKLM:\SOFTWARE\Policies\Coriqo\Shield'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name EnrolToken -Value $key -Force | Out-Null
New-ItemProperty -Path $k -Name ServerUrl -Value $server -Force | Out-Null
# Run in the user's context (Intune: "Run this script using the logged on credentials" = Yes):
& "$env:LOCALAPPDATA\Coriqo\venv\Scripts\byoai-shield.exe" enrol --jitter-seconds 120
$status = $LASTEXITCODE
& "$env:LOCALAPPDATA\Coriqo\venv\Scripts\byoai-shield.exe" --install-login-item
Remove-ItemProperty -Path $k -Name EnrolToken   # nothing left in the registry once enrolled
exit $status
```

Writing to `HKLM` needs administrator rights and reading the user's profile
needs the user's, so in practice the script is split in two Intune steps: one
as SYSTEM that writes the registry values, one as the user that runs `enrol`;
remove `EnrolToken` after the second. Shield install until a signed `.msi`
exists: `py -m venv "$env:LOCALAPPDATA\Coriqo\venv"` then
`...\Scripts\pip install --pre "byoai-runtime[shield]"`. Requires Python 3 on
the computer.

### File or preference on Linux and other tools

Any tool that can write a root-owned file works. The file is JSON, not
writable by group or other, at `/etc/coriqo/shield/enrol.json` (Linux),
`/Library/Application Support/Coriqo/Shield/enrol.json` (macOS) or
`%ProgramData%\Coriqo\Shield\enrol.json` (Windows):

```json
{"token": "<CLIENT_ENROLMENT_KEY>", "server_url": "https://shield.example.com"}
```

The server address must start with `https://`. The full list of locations is in
`CONFIGURATION.md`, "Shield enrolment by device-management tool".

### Finding computers that are not enrolled (`discover --send`)

For machines that never enrol, `byoai-shield discover --send` uploads a name-only report of the AI tools found
there. It needs the Endpoint discovery add-on and a **discovery key** (Coriqo, Settings, Endpoint discovery; shown
once). The key is separate from the enrolment key, is accepted by the report upload only, and can be rotated or
revoked there. Deploy it the same way as the enrolment key but under the names `DiscoveryKey` and `ServerUrl`
(registry or managed preference) or the file `discover.json` with `{"key": ..., "server_url": ...}`, root-owned and
not writable by group or other. Then schedule `byoai-shield discover --send --jitter-seconds 600` as the signed-in
user, daily is plenty. Reports are unverified sightings: they show as ungoverned until someone matches them.
Ready scripts: `examples/shield_discover_mdm/` (`jamf.sh`, `intune.ps1`, `linux-cron.md`). Exit codes are in
`CONFIGURATION.md`.

## Limits and what to do when it fails

`byoai-shield enrol` tries up to three times. It retries only a response of
HTTP 429, 502, 503 or 504, waiting about 1 to 3 seconds, then 2 to 6 seconds.
Anything else, including a timeout (15 seconds per try) or a connection
error, fails at once with exit 1 and the reason on stderr. Retrying a refusal does not help, so the command does not.

| Symptom | Cause | What to do |
|---|---|---|
| `HTTP 404` "Invalid, expired, or already-used enrolment token" | The key is unknown, expired or revoked, or was mistyped. Coriqo gives the same answer for all of these on purpose | Do not retry. Check the key's state on the Enrol tab and create a new key if it is not Active. Every 404 counts against the per-address budget below |
| `HTTP 409` "This enrolment key has enrolled all N devices it allows" | The key reached its device limit | Create a new key with a higher limit, or revoke a device that is gone. Retrying does not help |
| `HTTP 409` "That public key is already enrolled to a device in this tenant" | This computer's user enrolled before. Often the first try reached the server and its answer was lost, so the computer holds no enrolment state | Find the device on the client's Devices tab and revoke it, then run `enrol` again. The refused try does not spend a place on the key |
| `HTTP 429` "receiving enrolments faster than its limit" | The key's budget: 60 enrolments a minute by default | The command already retries. If it still ends with exit 1, the next run (next login, or your MDM's retry) finishes. Ask your Coriqo administrator to raise the limit if rollouts are slow |
| `HTTP 429` "Too many enrolment attempts with a wrong key or token" | The address sent too many wrong keys or tokens (10 in 15 minutes in production; the operator can change it) | Fix the key first. The address is refused for up to 15 minutes, even with a valid key. Retry after the window |
| `HTTP 423` read-only lockdown | Coriqo's nightly check found a broken audit chain for this client | Ask your Coriqo administrator. Enrolment resumes when the lock is cleared |
| Exit 1, "enrollment request failed" (timeout, no route) | The computer cannot reach the server address | Check the address and the network from that computer. A first try that timed out may still have reached the server: if the next run says 409 "already enrolled", revoke the device on the Devices tab and run again |
| Exit 1 on HTTP 500 or another 5xx not listed above | Server error. Not retried by the command | Run again later. If it repeats, contact Coriqo support |
| Exit 2 | The key, the address or the file permissions are missing or wrong | Read the message; it names what to set |

## Rolling out to many clients

- One key per client. Create the keys one client at a time in the console.
  Bulk client creation and a CSV export of keys are not built.
- Set **Device limit** to the number of computers, plus a few spare. Enrolment
  is per user (the device key lives in the user's own folder), so a computer
  used by more than one person may take more than one place. This has not been
  checked against the server's count: enrol one shared computer and read the
  key's "used" count to confirm.
- A key accepts 60 enrolments a minute by default. `--jitter-seconds 120`
  spreads computers over two minutes; 1,000 computers at one client would take
  about 17 minutes at that rate, so use a larger jitter (the command accepts up
  to 900 seconds) or ask your Coriqo administrator to raise the per-minute
  limit. Computers that hit the limit retry briefly, then exit 1 and finish on
  their next run.
- Successful enrolments do not use the per-address budget. An office of 50
  computers behind one internet address enrols without refusing itself. Only
  wrong or unknown keys and tokens count, so one wrong key in a script can
  block that address for up to 15 minutes, including for the right key.
- Run `enrol` on every login. It exits 0 at once on a computer that is already
  enrolled.
- Each enrolment is a record in that client's audit log with the device id,
  never the key.

## Security notes

- Treat the key like a password. Whoever holds it can enrol a computer into
  that client until it expires or fills.
- Keep it in the MDM secret store. Do not paste it in tickets, chat, scripts in
  a shared repository, or logs. The command does not print it.
- It is shown once, and Coriqo keeps only a hash. If lost, revoke it and create
  another.
- Keep the end date short (7 days by default, 30 at most) and the device limit
  near the real number of computers.
- To revoke a key, use **Revoke** on the Enrol tab. It stops at once.
- Computers already enrolled stay enrolled after a revoke. Revoke them one by
  one on the Devices tab.
- A second person approves every key, and the approval is part of the client's
  audit record.

## Fallback: single-use tokens

Use this for an older Coriqo (without reusable keys), one computer, or a
self-hosted Shield server. A token is single-use and expires within 24 hours,
so each computer needs its own. In the console, create the client and mint one
enrolment token per computer shortly before the push, and keep the list
private. Record the server address; it goes next to the token.

The scripts are the same as above with `EnrolToken` set to that computer's
token, looked up from a list you deploy (a `serial,token` CSV in the package,
read by serial number), and the token removed after `enrol`. Everything in "Limits" applies, except there is no
device limit: a spent token gives HTTP 404, the same as an unknown one. One token
cannot be pushed to many computers.

## Force-installing the extension and its managed settings

Replace `<EXTENSION_ID>` with the id of the build you distribute (see the next
section). `shield_port` must match `BYOAI_SHIELD_PORT` on Shield (default 17831).
Only those two settings exist: the extension builds `http://127.0.0.1:<port>/api/browser`
from the port and never takes a host, and still pairs by Shield's device key.

### Chrome policy JSON (any platform)

`ExtensionSettings`:

```json
{
  "<EXTENSION_ID>": {
    "installation_mode": "force_installed",
    "update_url": "https://clients2.google.com/service/update2/crx",
    "toolbar_pin": "force_pinned"
  }
}
```

`3rdparty` (the managed storage the extension reads):

```json
{
  "extensions": {
    "<EXTENSION_ID>": { "shield_port": 17831, "managed_by": "Contoso IT" }
  }
}
```

### Windows registry (Chrome, PowerShell)

```powershell
$id = '<EXTENSION_ID>'
$base = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
New-Item -Force "$base\ExtensionInstallForcelist" | Out-Null
Set-ItemProperty "$base\ExtensionInstallForcelist" -Name 1 -Value "$id;https://clients2.google.com/service/update2/crx"
New-Item -Force "$base\3rdparty\extensions\$id\policy" | Out-Null
Set-ItemProperty "$base\3rdparty\extensions\$id\policy" -Name shield_port -Value 17831 -Type DWord
Set-ItemProperty "$base\3rdparty\extensions\$id\policy" -Name managed_by -Value 'Contoso IT'
```

Intune can deliver the same through Settings catalog (Google Chrome >
Extensions) for the force-install, and a PowerShell script or the ADMX-backed
custom policy for the `3rdparty` values. For Edge use
`HKLM\SOFTWARE\Policies\Microsoft\Edge\...` with the same layout.

### macOS, Jamf configuration profile

Custom Settings payload, preference domain `com.google.Chrome`, property list:

```xml
<dict>
  <key>ExtensionSettings</key>
  <dict>
    <key>EXTENSION_ID</key>
    <dict>
      <key>installation_mode</key><string>force_installed</string>
      <key>update_url</key><string>https://clients2.google.com/service/update2/crx</string>
    </dict>
  </dict>
  <key>3rdparty</key>
  <dict><key>extensions</key><dict><key>EXTENSION_ID</key>
    <dict><key>shield_port</key><integer>17831</integer>
          <key>managed_by</key><string>Contoso IT</string></dict>
  </dict></dict>
</dict>
```

Verify on a machine at `chrome://policy` (both policies listed, no errors) and
the extension popup (address shows the managed port; "change address" is gone).

## Where the extension comes from (open decision)

Chrome force-install needs an `update_url`.

- Chrome Web Store: use `https://clients2.google.com/service/update2/crx` with the store id. Needs the listing published (see `internal_doc/chrome-store-submission.md`, still open). Simplest for admins.
- Self-hosted: host a signed `.crx` plus an update XML over https and point `update_url` at it. Chrome on Windows and macOS only accepts this for managed (domain-joined or MDM-enrolled) machines. The manifest `key` pins id `jbbongpiablbbmfflcaafjbeejeododc` for the unpacked build; the matching private key must be held by whoever signs the `.crx`.

## What a signed installer needs (not built here)

- macOS `.pkg`: an Apple Developer ID Installer certificate, Developer ID Application certificate for the bundled Python and binaries, notarisation (an app-specific password or API key), and a Jamf/Intune-friendly payload (the venv, the `byoai-shield` launcher, the login item, a postinstall that runs `enrol`).
- Windows `.msi`: an Authenticode code-signing certificate (EV preferred, for SmartScreen), a bundled Python runtime, WiX or equivalent, a per-user install path, and a custom action that runs `enrol`.
- Both: a build pipeline that pins the Shield version, produces checksums, and publishes to a location the MDM can fetch from over https.
