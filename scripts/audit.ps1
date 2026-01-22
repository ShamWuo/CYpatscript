# CyberPatriot Audit Policy Script
# Purpose: Enable comprehensive auditing and security registry settings
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Audit_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Audit Policy Script" "INFO"

# 1. Audit Policies (using auditpol.exe)
# Categories: Account Logon, Account Management, Logon/Logoff, Policy Change, Object Access
$AuditCategories = @(
    "Account Logon",
    "Account Management",
    "Logon/Logoff",
    "Policy Change",
    "Object Access"
)

foreach ($Category in $AuditCategories) {
    try {
        # Auditpol requires admin.
        # Syntax: auditpol /set /subcategory:"Name" /success:enable /failure:enable
        # Problem: "Account Logon" is a Category. auditpol sets subcategories or categories.
        # Using /category avoids checking every subcategory name which differs by OS sometimes.
        
        $Process = Start-Process -FilePath "auditpol.exe" -ArgumentList "/set /category:`"$Category`" /success:enable /failure:enable" -PassThru -Wait -NoNewWindow
        
        if ($Process.ExitCode -eq 0) {
            Log-Action "Enabled auditing for category: $Category" "SUCCESS"
        } else {
            Log-Action "Failed to set audit policy for $Category. Exit Code: $($Process.ExitCode)" "ERROR"
        }
    } catch {
        Log-Action "Error executing auditpol: $_" "ERROR"
    }
}

# 2. Security Registry Settings

# Disable LM Hash
try {
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $Key -Name "NoLMHash" -Value 1 -ErrorAction Stop
    Log-Action "Disabled LM Hash storage." "SUCCESS"
} catch {
    Log-Action "Failed to disable LM Hash: $_" "ERROR"
}

# Require Ctrl+Alt+Del for login
try {
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $Key -Name "DisableCAD" -Value 0 -ErrorAction Stop
    Log-Action "Required Ctrl+Alt+Del for login." "SUCCESS"
} catch {
    Log-Action "Failed to require Ctrl+Alt+Del: $_" "ERROR"
}

# Restrict Anonymous Access
try {
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $Key -Name "RestrictAnonymous" -Value 1 -ErrorAction Stop
    Log-Action "Restricted anonymous access (Level 1)." "SUCCESS"
} catch {
    Log-Action "Failed to restrict anonymous access: $_" "ERROR"
}

Log-Action "Audit Script Completed." "INFO"
Start-Sleep -Seconds 5
