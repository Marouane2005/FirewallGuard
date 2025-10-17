# Example: How to use FirewallGuard Parser
# Author: Marouane @Marouane2005

# Import the module
Import-Module .\src\parser\FirewallParser.psm1 -Force

Write-Host @"
╔═══════════════════════════════════════════════════════╗
║          FIREWALLGUARD - LOG ANALYZER                 ║
╚═══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Parse the firewall log
$logPath = "C:\SecurityLab\Logs\firewall.log"
$events = Parse-FirewallLog -LogPath $logPath -TailLines 1000

if ($events.Count -eq 0) {
    Write-Host "[!] No events found. Make sure logging is enabled." -ForegroundColor Yellow
    exit
}

# Display statistics
Write-Host "`n[*] EVENT STATISTICS" -ForegroundColor Yellow
Write-Host "=" * 70

$stats = Get-EventStatistics -Events $events

Write-Host "Total Events: " -NoNewline; Write-Host $stats.TotalEvents -ForegroundColor Cyan
Write-Host "Blocked (DROP): " -NoNewline; Write-Host $stats.BlockedEvents -ForegroundColor Red
Write-Host "Allowed (ALLOW): " -NoNewline; Write-Host $stats.AllowedEvents -ForegroundColor Green
Write-Host "TCP Events: " -NoNewline; Write-Host $stats.TCPEvents -ForegroundColor White
Write-Host "UDP Events: " -NoNewline; Write-Host $stats.UDPEvents -ForegroundColor White
Write-Host "Unique Source IPs: " -NoNewline; Write-Host $stats.UniqueSourceIPs -ForegroundColor Magenta
Write-Host "Time Range: " -NoNewline; Write-Host "$($stats.TimeRange.Start) to $($stats.TimeRange.End)" -ForegroundColor Gray

# Find suspicious activity
Write-Host "`n[*] THREAT DETECTION" -ForegroundColor Yellow
Write-Host "=" * 70

$threats = Find-SuspiciousActivity -Events $events

if ($threats.Count -gt 0) {
    foreach ($threat in $threats) {
        Write-Host "`n🚨 $($threat.Type) - Severity: $($threat.Severity)" -ForegroundColor Red
        Write-Host "   Source IP: $($threat.SourceIP)" -ForegroundColor Yellow
        Write-Host "   $($threat.Description)" -ForegroundColor White
    }
} else {
    Write-Host "`n✅ No threats detected!" -ForegroundColor Green
}

# Top Blocked IPs
Write-Host "`n[*] TOP 10 BLOCKED SOURCE IPs" -ForegroundColor Yellow
Write-Host "=" * 70

$events | 
    Where-Object { $_.Action -eq "DROP" } |
    Group-Object SourceIP |
    Sort-Object Count -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        Write-Host "$($_.Name): " -NoNewline -ForegroundColor Cyan
        Write-Host "$($_.Count) blocked attempts" -ForegroundColor Red
    }

Write-Host "`n[✓] Analysis complete!" -ForegroundColor Green
