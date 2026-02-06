# Check-NotepadPlusPlusIOC

A PowerShell script that scans a Windows machine for indicators of compromise (IOCs) related to the [Notepad++ supply chain attack](https://securelist.com/notepad-supply-chain-attack/118708/) documented by Kaspersky.

## What It Checks

- **Malware directories** - Known staging directories used by the attack (`%APPDATA%\ProShow\`, `%APPDATA%\Adobe\Scripts\`, `%APPDATA%\Bluetooth\`)
- **Malware files** - Specific payload, config, backdoor, and recon output files
- **Suspicious processes** - Running processes matching known malicious names (`ProShow`, `GUP`, `BluetoothService`)
- **C2 network connections** - Active TCP connections to known command-and-control IP addresses
- **C2 DNS cache** - DNS cache entries for known C2 domains
- **Notepad++ plugins** - Non-default plugin folders that may indicate a malicious plugin
- **SHA1 hash matching** - Files in suspected directories checked against 25 known malicious file hashes

## Requirements

- Windows PowerShell 5.1 or later
- Some checks (network connections, DNS cache) may require elevated privileges for full results

## Usage

```powershell
.\Check-NotepadPlusPlusIOC_JPR2.ps1
```

If your execution policy prevents running the script, you can bypass it for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The script outputs a color-coded table of results:

| Status    | Meaning                                      |
|-----------|----------------------------------------------|
| `CLEAN`   | No indicators found for this check           |
| `FOUND`   | IOC detected — investigate immediately       |
| `WARNING` | Check could not complete or needs review      |

## Example Output

```
=== Notepad++ Supply Chain Attack IOC Check ===
Machine : WORKSTATION01
User    : jdoe
Date    : 2026-01-15 14:30:00
Reference: https://securelist.com/notepad-supply-chain-attack/118708/

%APPDATA%\ProShow\ directory              [CLEAN]    Not found
%APPDATA%\Adobe\Scripts\ directory         [CLEAN]    Not found
%APPDATA%\Bluetooth\ directory             [CLEAN]    Not found
...
SHA1 hash matches                          [CLEAN]    No known malicious hashes found

RESULT: No indicators of compromise detected.
```

## License

[MIT](LICENSE)
