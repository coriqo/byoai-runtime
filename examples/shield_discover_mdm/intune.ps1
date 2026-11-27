# Intune PowerShell script: upload this PC's `byoai-shield discover` report to Coriqo.
# Two steps because HKLM needs administrator rights and the scan needs the user's profile.
# Step 1: run as SYSTEM (one-off, or on each key rotation). Writes the key to HKLM, where only admins can write.
#   $key = '<DISCOVERY_KEY>'   # from your secret store, not typed into the script
#   $k = 'HKLM:\SOFTWARE\Policies\Coriqo\Shield'
#   New-Item -Path $k -Force | Out-Null
#   New-ItemProperty -Path $k -Name DiscoveryKey -Value $key -Force | Out-Null
#   New-ItemProperty -Path $k -Name ServerUrl -Value 'https://coriqo.example.com' -Force | Out-Null
#
# Step 2: this script, with "Run this script using the logged on credentials" = Yes, repeated daily
# (Intune remediation script, or a scheduled task created by the Win32 app).
$exe = Join-Path $env:LOCALAPPDATA 'Coriqo\venv\Scripts\byoai-shield.exe'
if (-not (Test-Path $exe)) { exit 0 }          # Shield not installed here: nothing to do, stay quiet
& $exe discover --send --jitter-seconds 600 *> $null   # key and address come from HKLM, not from arguments
exit $LASTEXITCODE
