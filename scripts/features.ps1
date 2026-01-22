# CyberPatriot Windows Features Script
# Purpose: Disable dangerous Windows features
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Features_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Windows Features Script" "INFO"

# List of features to disable
$Features = @(
    "SMB1Protocol",           # SMBv1 (WannaCry vector)
    "TelnetClient",           # Telnet
    "TFTP",                   # TFTP Client
    "SimpleTCP",              # Simple TCP Services
    "LPDPrintService"         # Line Printer Daemon
)

foreach ($Feature in $Features) {
    try {
        $State = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue
        
        if ($State -and $State.State -eq "Enabled") {
            Log-Action "Disabling Feature: $Feature..." "INFO"
            # -NoRestart prevents immediate reboot, logs will show it enabled until reboot
            Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction Stop
            Log-Action "Disabled $Feature." "SUCCESS"
        } elseif ($State.State -eq "Disabled") {
            Log-Action "$Feature is already disabled." "INFO"
        }
    } catch {
        Log-Action "Error managing feature $Feature : $_" "INFO" # degrade to info as some features might not exist on all Win versions
    }
}

Log-Action "Features Script Completed. REBOOT REQUIRED." "INFO"
Start-Sleep -Seconds 5
