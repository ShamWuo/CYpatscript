# CyberPatriot Windows Updates & Security
# Purpose: Enable Windows Updates and Windows Defender
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Updates_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Windows Updates & Security Script" "INFO"

# 1. Windows Update Configuration
try {
    Log-Action "Configuring Windows Update policies..." "INFO"
    $Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (!(Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    
    # 4 = Auto download and schedule the install
    Set-ItemProperty -Path $Key -Name "AUOptions" -Value 4 -ErrorAction Stop
    Set-ItemProperty -Path $Key -Name "NoAutoUpdate" -Value 0 -ErrorAction Stop
    
    Log-Action "Windows Update set to Auto-Download and Install." "SUCCESS"
} catch {
     Log-Action "Failed to configure Windows Update: $_" "ERROR"
}

# 2. Windows Defender
try {
    Log-Action "Enabling Windows Defender Real-Time Protection..." "INFO"
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Log-Action "Real-Time Protection Enabled." "SUCCESS"
    
    Log-Action "Updating Windows Defender Signatures..." "INFO"
    Update-MpSignature -ErrorAction SilentlyContinue
    Log-Action "Defender update command issued." "SUCCESS"
} catch {
    Log-Action "Error managing Windows Defender: $_" "ERROR"
}

Log-Action "Updates Script Completed." "INFO"
Start-Sleep -Seconds 5
