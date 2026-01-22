# CyberPatriot Password Policy Script
# Purpose: Set strong password policies and account lockout settings
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Passwords_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Password Policy Script" "INFO"

# Helper to run net accounts
function Set-NetAccount {
    param($Args, $Desc)
    try {
        $Process = Start-Process -FilePath "net" -ArgumentList $Args -PassThru -Wait -NoNewWindow
        if ($Process.ExitCode -eq 0) {
            Log-Action "Successfully set $Desc" "SUCCESS"
        } else {
            Log-Action "Failed to set $Desc. Exit code: $($Process.ExitCode)" "ERROR"
        }
    } catch {
        Log-Action "Error executing net accounts: $_" "ERROR"
    }
}

# 1. Password Policies
# Min length: 12
Set-NetAccount "accounts /minpwlen:12" "Minimum Password Length to 12"

# Max age: 90
Set-NetAccount "accounts /maxpwage:90" "Maximum Password Age to 90"

# Min age: 1
Set-NetAccount "accounts /minpwage:1" "Minimum Password Age to 1"

# History: 5
Set-NetAccount "accounts /uniquepw:5" "Password History to 5"

# 2. Account Lockout Policies
# Threshold: 5 attempts
Set-NetAccount "accounts /lockoutthreshold:5" "Lockout Threshold to 5"

# Duration: 30 mins
Set-NetAccount "accounts /lockoutduration:30" "Lockout Duration to 30 mins"

# Reset window: 30 mins
Set-NetAccount "accounts /lockoutwindow:30" "Lockout Window to 30 mins"

# 3. Complexity (Requires secedit as 'net accounts' doesn't cover complexity directly in a simple switch usually,
# however, simpler method for V1 is attempting to use secedit which is more robust).

Log-Action "Exporting current security policy..." "INFO"
$SecDb = "$env:TEMP\secpol.cfg"
try {
    secedit /export /cfg $SecDb | Out-Null
    
    if (Test-Path $SecDb) {
        $Content = Get-Content $SecDb
        
        # Modify Complexity
        if ($Content -match "PasswordComplexity = 0") {
             $Content = $Content -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
             Log-Action "Planned change: Enable Password Complexity" "INFO"
        }
        
        # Save and Import
        $Content | Set-Content $SecDb
        Log-Action "Applying updated security policy..." "INFO"
        secedit /configure /db c:\windows\security\local.sdb /cfg $SecDb /areas SECURITYPOLICY | Out-Null
        Log-Action "Security policy applied (Complexity)." "SUCCESS"
        
    } else {
        Log-Action "Failed to export security policy." "ERROR"
    }
} catch {
    Log-Action "Error managing complexity via secedit: $_" "ERROR"
}

Log-Action "Password Policy Script Completed." "INFO"
Start-Sleep -Seconds 5
