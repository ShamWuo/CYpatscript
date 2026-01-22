# CyberPatriot Prohibited Content Scanner
# Purpose: Scan for prohibited files and software
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Prohibited_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Prohibited Content Scanner" "INFO"

# 1. File Scanner
$Extensions = @(".mp3", ".mp4", ".avi", ".mkv", ".mov", ".flv")
$SearchPaths = @("C:\Users", "C:\Program Files", "C:\Program Files (x86)")
# Limit User search for speed/safety? No, search all.

Log-Action "Scanning for media files ($($Extensions -join ', ')) in common locations..." "INFO"

foreach ($Path in $SearchPaths) {
    if (Test-Path $Path) {
        try {
            $Files = Get-ChildItem -Path $Path -Include $Extensions -Recurse -ErrorAction SilentlyContinue -Force
            if ($Files) {
                foreach ($File in $Files) {
                    Log-Action "FOUND PROHIBITED FILE: $($File.FullName)" "WARNING"
                }
            }
        } catch {
             Log-Action "Error scanning path $Path : $_" "ERROR"
        }
    }
}
Log-Action "File Scan Complete. Review log for files to delete manually." "INFO"

# 2. Software Scanner
Log-Action "Scanning installed software..." "INFO"

$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$SuspiciousKeywords = @("hack", "crack", "torrent", "mapper", "nmap", "wireshark", "cain", "netcat", "john", "ripper")

foreach ($Key in $UninstallKeys) {
    try {
        $Entries = Get-ChildItem -Path $Key -ErrorAction SilentlyContinue
        foreach ($Entry in $Entries) {
            $Values = Get-ItemProperty -Path $Entry.PSPath
            $DisplayName = $Values.DisplayName
            
            if ($DisplayName) {
                foreach ($Keyword in $SuspiciousKeywords) {
                    if ($DisplayName -match $Keyword) {
                        Log-Action "POTENTIALLY PROHIBITED SOFTWARE: $DisplayName" "WARNING"
                    }
                }
                
                # Check for games usually prohibited? (e.g. Steam, Minecraft which is java usually but still)
                if ($DisplayName -match "Steam" -or $DisplayName -match "Game") {
                     Log-Action "POTENTIAL GAME: $DisplayName" "WARNING"
                }
            }
        }
    } catch {
        Log-Action "Error scanning registry key $Key : $_" "ERROR"
    }
}

Log-Action "Software Scan Complete." "INFO"
Start-Sleep -Seconds 5
