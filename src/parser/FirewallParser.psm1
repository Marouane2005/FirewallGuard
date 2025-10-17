<#
.SYNOPSIS
    Windows Firewall Log Parser
.DESCRIPTION
    Parses Windows Firewall logs and extracts security events
.AUTHOR
    Marouane - @Marouane2005
#>

class FirewallEvent {
    [datetime]$DateTime
    [string]$Action
    [string]$Protocol
    [string]$SourceIP
    [string]$DestIP
    [int]$SourcePort
    [int]$DestPort
    [string]$Direction
    [int]$ProcessID
}

function Parse-FirewallLog {
    <#
    .SYNOPSIS
        Parse Windows Firewall log file
    .PARAMETER LogPath
        Path to pfirewall.log file
    .PARAMETER TailLines
        Number of recent lines to parse (default: 1000)
    .EXAMPLE
        Parse-FirewallLog -LogPath "C:\SecurityLab\Logs\firewall.log" -TailLines 500
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$false)]
        [int]$TailLines = 1000
    )
    
    Write-Host "[*] Parsing firewall log: $LogPath" -ForegroundColor Cyan
    
    if (-not (Test-Path $LogPath)) {
        Write-Error "Log file not found: $LogPath"
        return
    }
    
    $events = @()
    $lines = Get-Content $LogPath -Tail $TailLines
    $parsedCount = 0
    
    foreach ($line in $lines) {
        # Skip header lines
        if ($line -match "^#" -or $line -match "^$") {
            continue
        }
        
        # Parse log line
        # Format: date time action protocol src-ip dst-ip src-port dst-port size ...
        $fields = $line -split '\s+'
        
        if ($fields.Count -ge 9) {
            try {
                $event = [FirewallEvent]::new()
                $event.DateTime = [datetime]::Parse("$($fields[0]) $($fields[1])")
                $event.Action = $fields[2]
                $event.Protocol = $fields[3]
                $event.SourceIP = $fields[4]
                $event.DestIP = $fields[5]
                $event.SourcePort = [int]$fields[6]
                $event.DestPort = [int]$fields[7]
                
                # Find direction and PID from remaining fields
                for ($i = 8; $i -lt $fields.Count; $i++) {
                    if ($fields[$i] -match "SEND|RECEIVE") {
                        $event.Direction = $fields[$i]
                    }
                    if ($fields[$i] -match "^\d+$" -and $i -eq ($fields.Count - 1)) {
                        $event.ProcessID = [int]$fields[$i]
                    }
                }
                
                $events += $event
                $parsedCount++
            }
            catch {
                # Skip malformed lines
                continue
            }
        }
    }
    
    Write-Host "[+] Parsed $parsedCount events" -ForegroundColor Green
    return $events
}

function Get-EventStatistics {
    <#
    .SYNOPSIS
        Generate statistics from parsed firewall events
    .PARAMETER Events
        Array of FirewallEvent objects
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [FirewallEvent[]]$Events
    )
    
    $stats = @{
        TotalEvents = $Events.Count
        BlockedEvents = ($Events | Where-Object { $_.Action -eq "DROP" }).Count
        AllowedEvents = ($Events | Where-Object { $_.Action -eq "ALLOW" }).Count
        TCPEvents = ($Events | Where-Object { $_.Protocol -eq "TCP" }).Count
        UDPEvents = ($Events | Where-Object { $_.Protocol -eq "UDP" }).Count
        UniqueSourceIPs = ($Events | Select-Object -ExpandProperty SourceIP -Unique).Count
        UniqueDestIPs = ($Events | Select-Object -ExpandProperty DestIP -Unique).Count
        TimeRange = @{
            Start = ($Events | Measure-Object -Property DateTime -Minimum).Minimum
            End = ($Events | Measure-Object -Property DateTime -Maximum).Maximum
        }
    }
    
    return $stats
}

function Find-SuspiciousActivity {
    <#
    .SYNOPSIS
        Detect suspicious patterns in firewall events
    .PARAMETER Events
        Array of FirewallEvent objects
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [FirewallEvent[]]$Events
    )
    
    Write-Host "[*] Analyzing events for suspicious activity..." -ForegroundColor Yellow
    
    $findings = @()
    
    # 1. Port Scanning Detection
    $portScans = $Events | 
        Group-Object SourceIP | 
        Where-Object { 
            ($_.Group | Select-Object -ExpandProperty DestPort -Unique).Count -gt 10 
        } | 
        ForEach-Object {
            @{
                Type = "Port Scan"
                Severity = "High"
                SourceIP = $_.Name
                TargetPorts = ($_.Group | Select-Object -ExpandProperty DestPort -Unique).Count
                EventCount = $_.Count
                Description = "Source IP $($_.Name) attempted to connect to $($_.Group.DestPort.Count) different ports"
            }
        }
    
    $findings += $portScans
    
    # 2. Brute Force Detection (many blocked attempts)
    $bruteForce = $Events | 
        Where-Object { $_.Action -eq "DROP" } |
        Group-Object SourceIP | 
        Where-Object { $_.Count -gt 50 } |
        ForEach-Object {
            @{
                Type = "Potential Brute Force"
                Severity = "High"
                SourceIP = $_.Name
                AttemptCount = $_.Count
                Description = "Source IP $($_.Name) had $($_.Count) blocked connection attempts"
            }
        }
    
    $findings += $bruteForce
    
    # 3. Suspicious Ports
    $suspiciousPorts = @(4444, 5555, 1337, 31337, 12345, 6667)
    $suspiciousConnections = $Events | 
        Where-Object { $suspiciousPorts -contains $_.DestPort -or $suspiciousPorts -contains $_.SourcePort } |
        ForEach-Object {
            @{
                Type = "Suspicious Port"
                Severity = "Critical"
                SourceIP = $_.SourceIP
                DestIP = $_.DestIP
                Port = if ($suspiciousPorts -contains $_.DestPort) { $_.DestPort } else { $_.SourcePort }
                Description = "Connection involving known malicious port"
            }
        }
    
    $findings += $suspiciousConnections
    
    Write-Host "[+] Found $($findings.Count) suspicious activities" -ForegroundColor $(if ($findings.Count -gt 0) { "Red" } else { "Green" })
    
    return $findings
}

# Export functions
Export-ModuleMember -Function Parse-FirewallLog, Get-EventStatistics, Find-SuspiciousActivity
