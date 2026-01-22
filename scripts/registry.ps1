# CyberPatriot Registry Hardening
# Purpose: Apply miscellaneous registry hardening keys
# Author: Antigravity
# Version: 1.0

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Registry_" + (Get-Date -Format "HHmmss") + ".txt")

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

function Set-Reg {
    param($Path, $Name, $Value, $Type="DWord", $Desc)
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Log-Action "Set $Desc ($Name=$Value)" "SUCCESS"
    } catch {
        Log-Action "Failed to set $Desc : $_" "ERROR"
    }
}

Log-Action "Starting Registry Hardening" "INFO"

# 1. Disable storage of LM Hash (Critical Point)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" 1 "DWord" "Disable LM Hash"

# 2. Disable AutoRun (Prevent USB malware spread)
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord" "Disable AutoRun"

# 3. Screen Saver Security
# Enable Screen Saver
Set-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveActive" 1 "String" "Enable Screen Saver"
# Secure (Password Protect)
Set-Reg "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure" 1 "String" "Password Protect Screen Saver"
# Timeout (10 mins = 600s)
Set-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut" 600 "String" "Screen Saver Timeout 10m"

# 4. Hide last username on logon screen
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "dontdisplaylastusername" 1 "DWord" "Hide Last Username"

# 5. Disable Sticky Keys (Accessibility Backdoor vector)
# HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys -> Flags = "506" (Default is 510/511)
# Checking valid safe value (usually "506" turns off hotkey)
Set-Reg "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506" "String" "Disable Sticky Keys Hotkey"

Log-Action "Registry Hardening Completed." "INFO"
Start-Sleep -Seconds 5
