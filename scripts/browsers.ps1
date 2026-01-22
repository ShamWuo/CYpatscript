# CyberPatriot Browser Hardening Script
# Purpose: Secure Firefox and Chrome settings
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Browsers_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Browser Hardening Script" "INFO"

# 1. MOZILLA FIREFOX
# Firefox usually stores settings in `prefs.js` in the user profile, but for system-wide enforcement, 
# policies.json or local-settings.js is better. We will try creating a policies.json.

$FirefoxInstallDir = "C:\Program Files\Mozilla Firefox\distribution"
if (Test-Path "C:\Program Files (x86)\Mozilla Firefox") {
    $FirefoxInstallDir = "C:\Program Files (x86)\Mozilla Firefox\distribution"
}

if (Test-Path (Split-Path $FirefoxInstallDir -Parent)) {
    try {
        if (!(Test-Path $FirefoxInstallDir)) { New-Item -ItemType Directory -Force -Path $FirefoxInstallDir | Out-Null }
        
        $PoliciesJson = @{
            policies = @{
                DisableAppUpdate = $false
                AppUpdateURL = "https://www.mozilla.org/firefox/new/"
                DisableBuiltinPDFViewer = $true
                DisableFeedbackCommands = $true
                DisableFirefoxAccounts = $true
                DisablePocket = $true
                DisableTelemetry = $true
                PopupBlocking = @{
                    Default = $true
                }
                SearchBar = "unified"
            }
        }
        
        $JsonContent = $PoliciesJson | ConvertTo-Json -Depth 4
        Set-Content -Path (Join-Path $FirefoxInstallDir "policies.json") -Value $JsonContent
        Log-Action "Firefox policies.json created/updated." "SUCCESS"
    } catch {
        Log-Action "Error configuring Firefox: $_" "ERROR"
    }
} else {
    Log-Action "Firefox not installed." "INFO"
}

# 2. GOOGLE CHROME
# Chrome uses Registry policies.
$ChromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
try {
    if (!(Test-Path $ChromeKey)) { New-Item -Path $ChromeKey -Force | Out-Null }
    
    # Force SafeSearch
    Set-ItemProperty -Path $ChromeKey -Name "ForceGoogleSafeSearch" -Value 1 -ErrorAction SilentlyContinue
    # Enable Safe Browsing
    Set-ItemProperty -Path $ChromeKey -Name "SafeBrowsingEnabled" -Value 1 -ErrorAction SilentlyContinue
    # Block 3rd Party Cookies
    Set-ItemProperty -Path $ChromeKey -Name "BlockThirdPartyCookies" -Value 1 -ErrorAction SilentlyContinue
    # Password Manager (Usually disable saving just to be safe/secure)
    Set-ItemProperty -Path $ChromeKey -Name "PasswordManagerEnabled" -Value 0 -ErrorAction SilentlyContinue
    
    Log-Action "Chrome Registry Policies applied." "SUCCESS"
} catch {
    Log-Action "Error configuring Chrome: $_" "ERROR"
}

Log-Action "Browser Script Completed." "INFO"
Start-Sleep -Seconds 5
