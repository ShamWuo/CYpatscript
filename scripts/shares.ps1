# CyberPatriot Shares & Remote Access Script
# Purpose: Disable RDP and unauthorized shares
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Shares_" + (Get-Date -Format "HHmmss") + ".txt")

function Log-Action {
    param([string]$Message, [string]$Type = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp][$Type] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    
    switch ($Type) {
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        default   { Write-Host $LogEntry -ForegroundColor Gray }
    }
}

Log-Action "Starting Shares & Remote Access Script" "INFO"

# 1. Disable RDP
try {
    Log-Action "Disabling Remote Desktop..." "INFO"
    $RdpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    Set-ItemProperty -Path $RdpKey -Name "fDenyTSConnections" -Value 1 -ErrorAction Stop
    Log-Action "RDP Disabled (fDenyTSConnections=1)." "SUCCESS"
    
    # Also AllowTSConnections 0 in firewall, but we enabled firewall globally usually blocks it if RDP rule inactive.
} catch {
    Log-Action "Failed to disable RDP: $_" "ERROR"
}

# 2. Audit Shares
Log-Action "Auditing Network Shares..." "INFO"
try {
    $Shares = Get-SmbShare
    
    # Default shares: C$, ADMIN$, IPC$, print$, SYSVOL, NETLOGON (domain)
    # We want to remove anything else usually.
    $SafeShares = @("C$", "ADMIN$", "IPC$", "print$", "SYSVOL", "NETLOGON")
    
    foreach ($Share in $Shares) {
        if ($SafeShares -notcontains $Share.Name) {
            Log-Action "Suspicious Share Found: $($Share.Name) -> $($Share.Path)" "WARNING"
            
            # Action: Remove it? Prompt usually says remove unauthorized shares.
            # Safety: Log it, maybe remove if obvious.
            # I'll Remove it.
            try {
                Remove-SmbShare -Name $Share.Name -Force -ErrorAction Stop
                Log-Action "Removed unauthorized share: $($Share.Name)" "SUCCESS"
            } catch {
                Log-Action "Failed to remove share: $_" "ERROR"
            }
        }
    }
} catch {
    Log-Action "Error auditing shares: $_" "ERROR"
}

Log-Action "Shares Script Completed." "INFO"
Start-Sleep -Seconds 5
