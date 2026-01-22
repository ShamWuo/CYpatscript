# CyberPatriot Services & Firewall Script
# Purpose: Enable firewall and disable insecure services
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Services_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Services & Firewall Script" "INFO"

# 1. Firewall Configuration
try {
    Log-Action "Enabling Windows Firewall on all profiles..." "INFO"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Log-Action "Windows Firewall enabled successfully." "SUCCESS"
} catch {
    Log-Action "Failed to enable firewall: $_" "ERROR"
}

# 2. Service Management
    "RemoteRegistry",  # Remote Registry
    "TlntSvr",         # Telnet
    "MSFTPSVC",        # FTP Server (Microsoft)
    "SNMP",            # SNMP
    "RemoteAccess",    # Remote Access Auto Connection Manager
    "SSDPSRV",         # SSDP Discovery
    "upnphost",        # UPnP Device Host
    "XboxGipSvc",      # Xbox Accessory Management
    "XblAuthManager",  # Xbox Live Auth Manager
    "XblGameSave",     # Xbox Live Game Save
    "XboxNetApiSvc",   # Xbox Live Networking
    "MapsBroker",      # Downloaded Maps Manager
    "Fax",             # Fax Service
    "Spooler"          # Print Spooler (Check if printer is needed before keeping this!)
)

foreach ($ServiceName in $ServicesToDisable) {
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($Service) {
            # stop service if running
            if ($Service.Status -eq "Running") {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Log-Action "Stopped service: $ServiceName" "SUCCESS"
            }
            
            # disable startup type
            if ($Service.StartType -ne "Disabled") {
                Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                Log-Action "Disabled startup for service: $ServiceName" "SUCCESS"
            } else {
                 Log-Action "Service $ServiceName is already disabled." "INFO"
            }
        } else {
            Log-Action "Service not found (already clean?): $ServiceName" "INFO"
        }
    } catch {
        # Check if error is access denied or similar, specific handling not required but good for logs
        Log-Action "Error managing service $ServiceName : $_" "ERROR"
    }
}

Log-Action "Services Script Completed." "INFO"
Start-Sleep -Seconds 5
