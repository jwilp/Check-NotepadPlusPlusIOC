#Requires -Version 5.1
<#
.SYNOPSIS
    Checks for indicators of compromise (IOCs) related to the Notepad++ distribution compromise.

.DESCRIPTION
    Scans for filesystem artifacts, suspicious processes, known-bad hashes, and network/DNS indicators.
    Updated to include additional indicators from:
      - Validin (network pivots)
      - Kaspersky GReAT (execution chains, additional IoCs, hunting suggestions)

.PARAMETER IncludeDnsEventLog
    Also query the DNS Client operational event log for the last N days for IOC domains.

.PARAMETER DnsEventLogDays
    Number of days back to query DNS Client operational log (default 14).

.PARAMETER OutputJsonPath
    If provided, writes results to JSON.

.PARAMETER OutputCsvPath
    If provided, writes results to CSV.
#>

[CmdletBinding()]
param(
    [switch]$IncludeDnsEventLog,
    [ValidateRange(1,365)]
    [int]$DnsEventLogDays = 14,
    [string]$OutputJsonPath,
    [string]$OutputCsvPath
)

$ErrorActionPreference = 'SilentlyContinue'
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('CLEAN','FOUND','WARNING','INFO')][string]$Status,
        [Parameter(Mandatory)][string]$Details
    )
    $results.Add([PSCustomObject]@{
        Check   = $Check
        Status  = $Status
        Details = $Details
    })
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-DnsCacheEntries {
    if (-not (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue)) { return @() }

    try {
        $cache = Get-DnsClientCache -ErrorAction Stop
    } catch {
        return @()
    }
    foreach ($row in $cache) {
        $name =
            if ($row.PSObject.Properties.Name -contains 'Entry')         { $row.Entry }
            elseif ($row.PSObject.Properties.Name -contains 'Name')      { $row.Name }
            elseif ($row.PSObject.Properties.Name -contains 'RecordName'){ $row.RecordName }
            elseif ($row.PSObject.Properties.Name -contains 'HostName')  { $row.HostName }
            else { $null }

        if ($name) { $name.ToString().ToLowerInvariant() }
    }
}

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

# ---------------------------
# IOC SETS (Validin + Kaspersky)
# ---------------------------

# IP indicators
$c2Ips = @(
    '45.76.155.202',
    '61.4.102.97',
    '45.32.144.255',       # possible malicious download IP
    '95.179.213.0',        # initial download IP
    '45.77.31.210',
    '59.110.7.32',         # CS beacon IP (reported port 8880)
    '124.222.137.114',     # CS beacon IP (reported port 9999)
    '160.250.93.48',       # IP used by C2 domains
    '103.159.133.178'      # possible origin IP for wiresguard
) | ForEach-Object { $_.Trim() } | Sort-Object -Unique

# Kaspersky/Rapid7 port-specific beacons (higher signal than IP-only)
$ipPortIocs = @(
    @{ IP = '59.110.7.32';     Port = 8880; Note = 'CS beacon (reported)' },
    @{ IP = '124.222.137.114'; Port = 9999; Note = 'CS beacon (reported)' }
)

# Domain indicators (Kaspersky adds temp[.]sh as a LOLC2 artifact for chain #1/#2)
$c2Domains = @(
    'skycloudcenter.com',
    'api.skycloudcenter.com',
    'wiresguard.com',
    'api.wiresguard.com',
    'cloudtrafficservice.com',
    'api.cloudtrafficservice.com',
    'cdncheck.it.com',
    'safe-dns.it.com',
    'self-dns.it.com',
    'temp.sh'                 # Kaspersky: recon upload service used in chains #1/#2
) | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique

# ---------------------------
# FILESYSTEM CHECKS
# ---------------------------

$malwareDirs = @(
    @{ Name = '%APPDATA%\ProShow\';            Path = "$env:APPDATA\ProShow" },
    @{ Name = '%APPDATA%\Adobe\Scripts\';      Path = "$env:APPDATA\Adobe\Scripts" },
    @{ Name = '%APPDATA%\Bluetooth\';          Path = "$env:APPDATA\Bluetooth" },
    @{ Name = '%LOCALAPPDATA%\Temp\ns.tmp\';   Path = "$env:LOCALAPPDATA\Temp\ns.tmp" },   # Kaspersky: NSIS temp dir
    @{ Name = 'C:\ProgramData\USOShared\';     Path = "C:\ProgramData\USOShared" }         # Kaspersky/Rapid7: beacon observed here
)

foreach ($dir in $malwareDirs) {
    if (Test-Path -LiteralPath $dir.Path) {
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $dir.Path -Recurse -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName)
        } catch {
            Add-Result -Check "$($dir.Name) directory" -Status 'WARNING' -Details "Exists but could not enumerate contents (permissions or transient error)"
            continue
        }

        if ($files.Count -gt 0) {
            $sample = ($files | Select-Object -First 25) -join ', '
            $more = if ($files.Count -gt 25) { " ... (+$($files.Count-25) more)" } else { "" }
            Add-Result -Check "$($dir.Name) directory" -Status 'FOUND' -Details ("Contains: $sample$more")
        } else {
            Add-Result -Check "$($dir.Name) directory" -Status 'WARNING' -Details "Directory exists but appears empty"
        }
    } else {
        Add-Result -Check "$($dir.Name) directory" -Status 'CLEAN' -Details 'Not found'
    }
}

$malwareFiles = @(
    @{ Name = 'Payload: load';                 Path = "$env:APPDATA\ProShow\load" },
    @{ Name = 'Config: alien.ini';             Path = "$env:APPDATA\Adobe\Scripts\alien.ini" },
    @{ Name = 'Backdoor: BluetoothService';    Path = "$env:APPDATA\Bluetooth\BluetoothService" },
    @{ Name = 'NSIS temp dir: ns.tmp (dir)';   Path = "$env:LOCALAPPDATA\Temp\ns.tmp" },      # Kaspersky: directory
    @{ Name = 'Recon output: 1.txt';           Path = "$env:LOCALAPPDATA\Temp\1.txt" },
    @{ Name = 'Recon output: a.txt';           Path = "$env:LOCALAPPDATA\Temp\a.txt" }
)

foreach ($file in $malwareFiles) {
    if (Test-Path -LiteralPath $file.Path) {
        try {
            $item = Get-Item -LiteralPath $file.Path -Force -ErrorAction Stop
            if ($item.PSIsContainer) {
                Add-Result -Check $file.Name -Status 'FOUND' -Details "Directory exists: $($file.Path)"
            } else {
                Add-Result -Check $file.Name -Status 'FOUND' -Details "Size: $($item.Length) bytes, Modified: $($item.LastWriteTime)"
            }
        } catch {
            Add-Result -Check $file.Name -Status 'WARNING' -Details "Path exists but could not read metadata: $($file.Path)"
        }
    } else {
        Add-Result -Check $file.Name -Status 'CLEAN' -Details 'Not found'
    }
}

# ---------------------------
# PROCESS CHECKS
# ---------------------------

# Kaspersky describes GUP.exe launching malicious updater. Track GUP and known chain executables.
$suspiciousProcesses = @('proshow','gup','bluetoothservice','script')
$runningProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $suspiciousProcesses -contains ([string]$_.ProcessName).ToLowerInvariant()
}

if ($runningProcs) {
    $procNames = ($runningProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
    Add-Result -Check 'Suspicious processes' -Status 'FOUND' -Details "Running: $procNames"
} else {
    Add-Result -Check 'Suspicious processes' -Status 'CLEAN' -Details 'None running'
}

# ---------------------------
# NETWORK CONNECTION CHECKS
# ---------------------------

$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Add-Result -Check 'Privilege' -Status 'WARNING' -Details 'Not running as Administrator; some network/diagnostic queries may be incomplete'
} else {
    Add-Result -Check 'Privilege' -Status 'INFO' -Details 'Running as Administrator'
}

if (-not (Test-CommandExists -Name 'Get-NetTCPConnection')) {
    Add-Result -Check 'Connections to IOC IPs' -Status 'WARNING' -Details 'Get-NetTCPConnection not available on this system'
    Add-Result -Check 'Connections to IOC IP:Port' -Status 'WARNING' -Details 'Get-NetTCPConnection not available on this system'
} else {
    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop

        # IP-only check (broad)
        # FIX: RemoteAddress can be an IPAddress type; cast to string to avoid false negatives.
        $matched = $connections | Where-Object { $c2Ips -contains ([string]$_.RemoteAddress) } |
            Select-Object RemoteAddress, RemotePort, LocalAddress, LocalPort, State, OwningProcess -Unique

        if ($matched) {
            $detail = ($matched | ForEach-Object {
                "PID=$($_.OwningProcess) $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]"
            }) -join '; '
            Add-Result -Check 'Connections to IOC IPs' -Status 'FOUND' -Details $detail
        } else {
            Add-Result -Check 'Connections to IOC IPs' -Status 'CLEAN' -Details 'None detected'
        }

        # IP:Port check (higher signal)
        $matchedIpPort = @()
        foreach ($c in $connections) {
            foreach ($ioc in $ipPortIocs) {
                # FIX: cast RemoteAddress to string for comparison
                if (([string]$c.RemoteAddress) -eq $ioc.IP -and $c.RemotePort -eq $ioc.Port) {
                    $matchedIpPort += [PSCustomObject]@{
                        RemoteAddress = $c.RemoteAddress
                        RemotePort    = $c.RemotePort
                        LocalAddress  = $c.LocalAddress
                        LocalPort     = $c.LocalPort
                        State         = $c.State
                        OwningProcess = $c.OwningProcess
                        Note          = $ioc.Note
                    }
                }
            }
        }
        $matchedIpPort = $matchedIpPort | Select-Object * -Unique

        if ($matchedIpPort) {
            $detail2 = ($matchedIpPort | ForEach-Object {
                "$($_.Note) PID=$($_.OwningProcess) $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]"
            }) -join '; '
            Add-Result -Check 'Connections to IOC IP:Port' -Status 'FOUND' -Details $detail2
        } else {
            Add-Result -Check 'Connections to IOC IP:Port' -Status 'CLEAN' -Details 'None detected'
        }
    } catch {
        Add-Result -Check 'Connections to IOC IPs' -Status 'WARNING' -Details 'Could not query Get-NetTCPConnection'
        Add-Result -Check 'Connections to IOC IP:Port' -Status 'WARNING' -Details 'Could not query Get-NetTCPConnection'
    }
}

# ---------------------------
# DNS CACHE CHECKS
# ---------------------------

if (-not (Test-CommandExists -Name 'Get-DnsClientCache')) {
    Add-Result -Check 'DNS cache: IOC domains' -Status 'WARNING' -Details 'Get-DnsClientCache not available on this system'
} else {
    try {
        $cacheEntries = @(Get-DnsCacheEntries) | Where-Object { $_ }
        $hits = New-Object System.Collections.Generic.List[string]

        foreach ($d in $c2Domains) {
            $escaped = [regex]::Escape($d)
            $pattern = "($escaped)$"
            $cacheEntries | Where-Object { $_ -eq $d -or $_ -like "*.$d" -or $_ -match $pattern } | ForEach-Object {
                $hits.Add($_)
            }
        }

        if ($hits.Count -gt 0) {
            $found = ($hits | Sort-Object -Unique) -join ', '
            Add-Result -Check 'DNS cache: IOC domains' -Status 'FOUND' -Details "Seen: $found"
        } else {
            Add-Result -Check 'DNS cache: IOC domains' -Status 'CLEAN' -Details 'None in cache'
        }
    } catch {
        Add-Result -Check 'DNS cache: IOC domains' -Status 'WARNING' -Details 'Could not query DNS cache'
    }
}

# ---------------------------
# OPTIONAL DNS CLIENT EVENT LOG HUNTING
# ---------------------------

if ($IncludeDnsEventLog) {
    $log = 'Microsoft-Windows-DNS-Client/Operational'
    $start = (Get-Date).AddDays(-1 * $DnsEventLogDays)

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -ErrorAction Stop

        $matches = New-Object System.Collections.Generic.List[string]
        foreach ($evt in $events) {
            $raw = $evt.Message
            if ($null -eq $raw) { $raw = '' }
            $msg = $raw.ToLowerInvariant()

            foreach ($d in $c2Domains) {
                if ($msg -like "*$d*") {
                    $matches.Add(("{0} {1} :: {2}" -f $evt.TimeCreated.ToString('s'), $evt.Id, $d))
                }
            }
        }

        if ($matches.Count -gt 0) {
            $uniq = $matches | Sort-Object -Unique
            $detail = ($uniq | Select-Object -First 50) -join '; '
            $more = if ($uniq.Count -gt 50) { ' ... (truncated)' } else { '' }
            Add-Result -Check "DNS event log ($DnsEventLogDays days)" -Status 'FOUND' -Details "$detail$more"
        } else {
            Add-Result -Check "DNS event log ($DnsEventLogDays days)" -Status 'CLEAN' -Details 'No matches found'
        }
    } catch {
        Add-Result -Check "DNS event log ($DnsEventLogDays days)" -Status 'WARNING' -Details "Could not query $log (may be disabled)"
    }
}

# ---------------------------
# NOTEPAD++ PLUGINS DIRECTORY CHECK
# ---------------------------

$nppPluginPath = "$env:APPDATA\Notepad++\plugins"
if (Test-Path -LiteralPath $nppPluginPath) {
    try {
        $pluginDirs = Get-ChildItem -LiteralPath $nppPluginPath -Directory -Force -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
        Add-Result -Check 'Notepad++ plugins' -Status 'WARNING' -Details 'Plugins directory exists but could not be enumerated'
        $pluginDirs = @()
    }
    $nonDefault = $pluginDirs | Where-Object { $_ -ne 'config' }
    if ($nonDefault) {
        Add-Result -Check 'Notepad++ plugins' -Status 'WARNING' -Details "Non-default folders: $($nonDefault -join ', ')"
    } else {
        Add-Result -Check 'Notepad++ plugins' -Status 'CLEAN' -Details 'Only default content'
    }
} else {
    Add-Result -Check 'Notepad++ plugins' -Status 'INFO' -Details 'Notepad++ not installed or no plugins dir'
}

# ---------------------------
# KASPERSKY: AUTORUN / PERSISTENCE HUNT (Run keys)
# ---------------------------

$autorunKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$autorunIndicators = @(
    '\ProShow\',
    '\Adobe\Scripts\',
    '\Bluetooth\',
    '\Temp\ns.tmp',
    'temp.sh',
    'cdncheck.it.com',
    'safe-dns.it.com',
    'self-dns.it.com',
    'skycloudcenter.com',
    'wiresguard.com'
) | ForEach-Object { $_.ToLowerInvariant() }

$autorunHits = New-Object System.Collections.Generic.List[string]

foreach ($k in $autorunKeys) {
    if (Test-Path -LiteralPath $k) {
        try {
            $props = Get-ItemProperty -LiteralPath $k
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $val = [string]$p.Value
                if ([string]::IsNullOrWhiteSpace($val)) { continue }

                $lval = $val.ToLowerInvariant()
                foreach ($needle in $autorunIndicators) {
                    if ($lval -like "*$needle*") {
                        $autorunHits.Add("$k :: $($p.Name) = $val")
                        break
                    }
                }
            }
        } catch { }
    }
}

if ($autorunHits.Count -gt 0) {
    Add-Result -Check 'Autoruns (Run keys)' -Status 'FOUND' -Details (($autorunHits | Sort-Object -Unique | Select-Object -First 25) -join '; ')
} else {
    Add-Result -Check 'Autoruns (Run keys)' -Status 'CLEAN' -Details 'No suspicious Run-key entries found by simple pattern match'
}

# ---------------------------
# SHA1 HASH CHECKS (add Kaspersky auxiliary hashes)
# ---------------------------

$knownSha1 = @(
    # Malicious updater.exe hashes (Kaspersky)
    '8e6e505438c21f3d281e1cc257abdbf7223b7f5a',
    '90e677d7ff5844407b9c073e3b7e896e078e11cd',
    '573549869e84544e3ef253bdba79851dcde4963a',
    '13179c8f19fbf3d8473c49983a199e6cb4f318f0',
    '4c9aac447bf732acc97992290aa7a187b967ee2c',
    '821c0cafb2aab0f063ef7e313f64313fc81d46cd',

    # Kaspersky/Rapid7 noted hashes (existing)
    'd7ffd7b588880cf61b603346a3557e7cce648c93',
    '94dffa9de5b665dc51bc36e2693b8a3a0a4cc6b8',
    '21a942273c14e4b9d3faa58e4de1fd4d5014a1ed',
    '7e0790226ea461bcc9ecd4be3c315ace41e1c122',
    'f7910d943a013eede24ac89d6388c1b98f8b3717',
    '73d9d0139eaf89b7df34ceeb60e5f8c7cd2463bf',
    'bd4915b3597942d88f319740a9b803cc51585c4a',
    'c68d09dd50e357fd3de17a70b7724f8949441d77',
    '813ace987a61af909c053607635489ee984534f4',
    '9fbf2195dee991b1e5a727fd51391dcc2d7a4b16',
    '07d2a01e1dc94d59d5ca3bdf0c7848553ae91a51',
    '3090ecf034337857f786084fb14e63354e271c5d',
    'd0662eadbe5ba92acbd3485d8187112543bcfbf5',
    '9c0eff4deeb626730ad6a05c85eb138df48372ce',

    # Kaspersky auxiliary hashes (new adds)
    # Chain #1 (ProShow abuse)
    '06a6a5a39193075734a32e0235bde0e979c27228', # load (existing)
    '9c3ba38890ed984a25abb6a094b5dbf052f22fa7', # load (existing)
    'defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c', # ProShow.exe
    '259cd3542dea998c57f67ffdd4543ab836e3d2a3', # defscr
    '46654a7ad6bc809b623c51938954de48e27a5618', # if.dnt
    '9df6ecc47b192260826c247bf8d40384aa6e6fd6', # proshow_e.bmp

    # Chain #2 (Lua staging)
    'ca4b6fe0c69472cd3d63b212eb805b7f65710d33', # alien.ini (existing)
    '0d0f315fd8cf408a483f8e2dd1e69422629ed9fd', # alien.ini (existing)
    '2a476cfb85fbf012fdbe63a37642c11afa5cf020', # alien.ini (existing)
    '6444dab57d93ce987c22da66b3706d5d7fc226da', # alien.dll
    '2ab0758dda4e71aee6f4c8e4c0265a796518f07d', # lua5.1.dll
    'bf996a709835c0c16cce1015e6d44fc95e08a38a'  # script.exe
) | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique

# Expand hash scanning paths to include Kaspersky/Rapid7 noted location
$hashCheckPaths = @(
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Bluetooth",
    "C:\ProgramData\USOShared",
    "$env:LOCALAPPDATA\Temp\ns.tmp"
)

$hashMatches = New-Object System.Collections.Generic.List[string]
foreach ($dir in $hashCheckPaths) {
    if (Test-Path -LiteralPath $dir) {
        try {
            Get-ChildItem -LiteralPath $dir -File -Recurse -Force -ErrorAction Stop | ForEach-Object {
                $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA1).Hash
                if ($h -and ($knownSha1 -contains $h.ToLowerInvariant())) {
                    $hashMatches.Add("$($_.FullName) [$h]")
                }
            }
        } catch {
            Add-Result -Check 'SHA1 hash matches' -Status 'WARNING' -Details "Could not fully enumerate/hash files under: $dir"
        }
    }
}

if ($hashMatches.Count -gt 0) {
    $detail = (($hashMatches | Sort-Object -Unique) -join '; ')
    Add-Result -Check 'SHA1 hash matches' -Status 'FOUND' -Details $detail
} else {
    Add-Result -Check 'SHA1 hash matches' -Status 'CLEAN' -Details 'No known malicious hashes found'
}

# ---------------------------
# OUTPUT
# ---------------------------

Write-Host ''
Write-Host "=== Notepad++ Distribution Compromise IOC Check ===" -ForegroundColor Cyan
Write-Host "Machine : $env:COMPUTERNAME"
Write-Host "User    : $env:USERNAME"
Write-Host "Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "References: Validin + Kaspersky GReAT IoCs" -ForegroundColor DarkGray
Write-Host ''

$results | ForEach-Object {
    $color = switch ($_.Status) {
        'CLEAN'   { 'Green' }
        'FOUND'   { 'Red' }
        'WARNING' { 'Yellow' }
        'INFO'    { 'Gray' }
    }
    $statusTag = "[$($_.Status)]"
    Write-Host ("{0,-40} {1,-10} {2}" -f $_.Check, $statusTag, $_.Details) -ForegroundColor $color
}

Write-Host ''
$foundCount = ($results | Where-Object { $_.Status -eq 'FOUND' }).Count
if ($foundCount -gt 0) {
    Write-Host "RESULT: $foundCount indicator(s) detected. Treat as suspicious until disproven." -ForegroundColor Red
} else {
    Write-Host 'RESULT: No indicators detected by this script.' -ForegroundColor Green
}
Write-Host ''

# Optional export
try {
    if ($OutputJsonPath) {
        $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputJsonPath -Encoding UTF8
        Write-Host "Wrote JSON: $OutputJsonPath" -ForegroundColor Gray
    }
    if ($OutputCsvPath) {
        $results | Export-Csv -NoTypeInformation -Path $OutputCsvPath -Encoding UTF8
        Write-Host "Wrote CSV : $OutputCsvPath" -ForegroundColor Gray
    }
} catch {
    Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
