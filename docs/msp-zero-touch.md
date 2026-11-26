# Zero-touch Shield deployment (MDM)

Goal: an administrator sets up Shield on many managed computers with two steps
and no per-machine clicks.

1. Create the clients and get an enrolment token for each computer from the
   Coriqo (or self-hosted Shield server) console.
2. Push one package or script from your device-management tool (Jamf, Intune,
   Kandji, a Windows startup script). It force-installs the browser extension,
   installs Shield, and enrols the computer.

This page says plainly what works today and what does not.

## What exists today

| Piece | Status |
|---|---|
| `byoai-shield enrol` reads token and server address from a managed registry key, macOS managed preference or root-owned file | Built (this repo) |
| Extension reads `shield_port` and `managed_by` from managed storage (`managed_schema.json`); the port is then not changeable by the person | Built (this repo), ships in the next extension release |
| Extension force-install by Chrome policy | Works with any extension id. The Chrome Web Store listing is not published yet, so there is no store id to put in the policy (see "Where the extension comes from") |
| Shield install on many computers | Not built. Today it is `pip install` per machine, and needs Python. A signed `.pkg` (macOS) and `.msi` (Windows) are the missing piece |
| One token per computer, issued in bulk | Server side, not in this repo. A token is single-use, so one token cannot be pushed to 1,000 computers |
| Trusting Shield's capture proxy (CA certificate, proxy settings) by profile | Not built. The browser-extension route below needs neither |

So the honest demo today is: policy-installed extension plus a scripted Shield
install and enrol per machine, with a per-computer token list. It is not yet
"one push, nothing else".

## Step 1: clients and tokens

On the server console, create the client and mint one enrolment token per
computer. A token is single-use and expires within 24 hours, so mint them
shortly before the push and keep the list private: a token is a credential.
Record the server address (`https://...`); it goes next to the token.

Check one computer by hand first:

```sh
byoai-shield enrol --server https://shield.example.com --token-file ./token.txt
```

Exit 0 means enrolled (or already enrolled). The command prints the tenant and
device, never the token.

## Step 2: the push

Run as the signed-in user, not root: the device key lives in that user's
`~/.byoai/shield`. Add `--jitter-seconds 120` so a thousand computers do not hit
the server in the same second; the command also retries a busy server
(HTTP 429/502/503/504) three times with backoff.

### macOS, Jamf Pro

Policy script (runs as root; `$3` is the signed-in user). The token list is a
two-column CSV `serial,token` deployed in the same policy or read from a Jamf
extension attribute; this version reads a CSV in the package payload.

```sh
#!/bin/bash
USER_NAME="$3"
SERIAL=$(ioreg -l | awk -F'"' '/IOPlatformSerialNumber/{print $4}')
TOKEN=$(awk -F, -v s="$SERIAL" '$1==s{print $2}' "/Library/Application Support/Coriqo/Shield/tokens.csv")
[ -z "$TOKEN" ] && { echo "no token for $SERIAL"; exit 1; }
DIR="/Library/Application Support/Coriqo/Shield"
umask 077
printf '{"token":"%s","server_url":"https://shield.example.com"}' "$TOKEN" > "$DIR/enrol.json"
chown root:wheel "$DIR/enrol.json"
chmod 644 "$DIR/enrol.json"   # the signed-in user must read it; root-owned and not writable by group or other, as enrol requires
sudo -u "$USER_NAME" -H /Users/"$USER_NAME"/.byoai/venv/bin/byoai-shield enrol --jitter-seconds 120
sudo -u "$USER_NAME" -H /Users/"$USER_NAME"/.byoai/venv/bin/byoai-shield --install-login-item
rm -f "$DIR/enrol.json"       # single-use: nothing left to steal
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
A profile carries one value for every computer it is scoped to, so use it with
a per-computer token only through Jamf's per-computer variables.

### Windows, Intune (PowerShell script or Win32 app, run as SYSTEM or user)

The registry route is the hardened one: only administrators can write
`HKLM`, so the command trusts it.

```powershell
$tokens = Import-Csv "$env:ProgramData\Coriqo\Shield\tokens.csv"   # serial,token
$serial = (Get-CimInstance Win32_BIOS).SerialNumber
$token  = ($tokens | Where-Object serial -eq $serial).token
if (-not $token) { throw "no token for $serial" }
$k = 'HKLM:\SOFTWARE\Policies\Coriqo\Shield'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name EnrolToken -Value $token -Force | Out-Null
New-ItemProperty -Path $k -Name ServerUrl -Value 'https://shield.example.com' -Force | Out-Null
# Run in the user's context (Intune: "Run this script using the logged on credentials" = Yes):
& "$env:LOCALAPPDATA\Coriqo\venv\Scripts\byoai-shield.exe" enrol --jitter-seconds 120
& "$env:LOCALAPPDATA\Coriqo\venv\Scripts\byoai-shield.exe" --install-login-item
Remove-ItemProperty -Path $k -Name EnrolToken   # single-use
```

Shield install until a signed `.msi` exists: `py -m venv "$env:LOCALAPPDATA\Coriqo\venv"` then
`...\Scripts\pip install --pre "byoai-runtime[shield]"`. Requires Python 3 on the machine.

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
