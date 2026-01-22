# CyberPatriot Software Management Script
# Purpose: Uninstall prohibited software
# Author: Antigravity
# Version: 1.0

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Software_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Software Management Script" "INFO"

# List of prohibited software matching strings (Case Insensitive)
$ProhibitedSoftware = @(
    "Wireshark",
    "Nmap",
    "Cain",
    "Abel",
    "Netcat",
    "John the Ripper",
    "Hydra",
    "Aircrack",
    "Metasploit",
    "Ophcrack",
    "Angry IP Scanner",
    "uTorrent",
    "BitTorrent",
    "Vuze",
    "WireShark",
    "ZenMap"
)

Log-Action "Scanning for prohibited software..." "INFO"

# Method 1: Get-Package (Modern Windows)
try {
    $Packages = Get-Package -ErrorAction SilentlyContinue
    foreach ($App in $Packages) {
        foreach ($BadApp in $ProhibitedSoftware) {
            if ($App.Name -like "*$BadApp*") {
                Log-Action "Found Prohibited Software: $($App.Name)" "WARNING"
                try {
                    Log-Action "Attempting to uninstall $($App.Name)..." "INFO"
                    Uninstall-Package -Name $App.Name -Force -ErrorAction Stop
                    Log-Action "Successfully uninstalled $($App.Name)" "SUCCESS"
                } catch {
                    Log-Action "Failed to uninstall $($App.Name) via Get-Package: $_" "ERROR"
                }
            }
        }
    }
} catch {
    Log-Action "Get-Package scan failed (Modules missing?)." "WARNING"
}

# Method 2: WMI (Fallback for older installs / MSI)
try {
    $WmiApps = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
    foreach ($App in $WmiApps) {
        foreach ($BadApp in $ProhibitedSoftware) {
            if ($App.Name -like "*$BadApp*") {
                Log-Action "Found Prohibited Software (WMI): $($App.Name)" "WARNING"
                try {
                    $App.Uninstall() | Out-Null
                    Log-Action "Successfully uninstalled $($App.Name)" "SUCCESS"
                } catch {
                    Log-Action "Failed to uninstall $($App.Name) via WMI: $_" "ERROR"
                }
            }
        }
    }
} catch {
    Log-Action "WMI scan error: $_" "WARNING"
}

Log-Action "Software Management Script Completed." "INFO"
Start-Sleep -Seconds 5
