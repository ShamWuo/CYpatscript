# CyberPatriot User Management Script
# Purpose: Remove unauthorized users and configure user accounts
# Author: Antigravity
# Version: 1.0
# Last Updated: 2026-01-22

# ==========================================
# CONFIGURATION SECTION
# ==========================================
$AuthorizedUsers = @("Administrator", "CyberPatriot", "Judge", "User1")
$AuthorizedAdmins = @("Administrator", "CyberPatriot")

# Try to load from config.json if it exists
$ConfigPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\config\config.json"
if (Test-Path $ConfigPath) {
    try {
        $Config = Get-Content $ConfigPath | ConvertFrom-Json
        if ($Config.authorizedUsers) { $AuthorizedUsers = $Config.authorizedUsers }
        if ($Config.authorizedAdmins) { $AuthorizedAdmins = $Config.authorizedAdmins }
        Write-Host "Configuration loaded from $ConfigPath" -ForegroundColor Cyan
    } catch {
        Write-Host "Error loading config.json, using script defaults." -ForegroundColor Yellow
    }
}

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Users_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting User Management Script" "INFO"

# ==========================================
# MAIN LOGIC
# ==========================================

# 1. Disable Guest Account
try {
    Log-Action "Checking Guest account status..." "INFO"
    $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($Guest) {
        if ($Guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Log-Action "Guest account disabled." "SUCCESS"
        } else {
            Log-Action "Guest account already disabled." "INFO"
        }
    } else {
        Log-Action "Guest account not found." "WARNING"
    }
} catch {
    Log-Action "Failed to disable Guest account: $_" "ERROR"
}

# 2. Manage Local Users
try {
    Log-Action "Auditing local users..." "INFO"
    $LocalUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    foreach ($User in $LocalUsers) {
        if ($AuthorizedUsers -notcontains $User.Name) {
            Log-Action "Unauthorized user found: $($User.Name). Disabling/Removing..." "WARNING"
            # In a real competition, renaming/disabling is safer than deleting first.
            # But requirements say "Remove". I will Disable for safety in V1, specifically noted in logs.
            # actually prompt says "Remove unauthorized local user accounts"
            # I'll disable them first then try to remove to be safe but compliant with "Remove" intent if possible, 
            # OR just disable to be safe. Let's Stick to Remove as per prompt requirement "Remove unauthorized local user accounts"
            # But wait, safety checking... I will Disable them required by "Safety Features -> Don't auto-delete files". 
            # Accounts are not files, but same logic applies. 
            # However, standard CyPat strategy is DELETE. I'll stick to DISABLE for safety in this V1 tool unless specified otherwise.
            # Actually, prompt says "Remove". I will Remove.
            
            Remove-LocalUser -Name $User.Name -ErrorAction Stop
            Log-Action "Removed user: $($User.Name)" "SUCCESS"
        } else {
            Log-Action "User authorized: $($User.Name)" "INFO"
            
            # Force Password Change (Expire Password)
            try {
                # This flag forces user to change password at next login
                $UserObj = [ADSI]"WinNT://$env:COMPUTERNAME/$($User.Name),user"
                if ($UserObj.PasswordExpired -ne 1) {
                    $UserObj.PasswordExpired = 1
                    $UserObj.SetInfo()
                    Log-Action "Forced password change for: $($User.Name)" "SUCCESS"
                }
            } catch {
                 Log-Action "Failed to expire password for $($User.Name): $_" "WARNING"
            }
        }
    }
} catch {
    Log-Action "Error auditing users: $_" "ERROR"
}

# 3. Manage Administrators Group
try {
    Log-Action "Auditing Administrators group..." "INFO"
    $AdminGroup = Get-LocalGroupMember -Group "Administrators"
    
    foreach ($Member in $AdminGroup) {
        # Member.Name format is usually "COMPUTER\User"
        $Username = $Member.Name.Split('\')[-1]
        
        # Skip checking built-in Administrator if needed, but it should be in authorized list
        if ($AuthorizedAdmins -notcontains $Username) {
            if ($Member.ObjectClass -eq "User") {
                Log-Action "Unauthorized admin found: $Username. Removing from group..." "WARNING"
                Remove-LocalGroupMember -Group "Administrators" -Member $Member.Name
                Log-Action "Removed $Username from Administrators." "SUCCESS"
            }
        } else {
             Log-Action "Admin authorized: $Username" "INFO"
        }
    }
    
    # Verify we didn't remove everyone (logic check)
    $RemainingAdmins = Get-LocalGroupMember -Group "Administrators"
    if ($RemainingAdmins.Count -eq 0) {
        Log-Action "CRITICAL: No administrators left! Attempting to add back current user..." "ERROR"
        Add-LocalGroupMember -Group "Administrators" -Member $env:USERNAME
    }

} catch {
    Log-Action "Error auditing admins: $_" "ERROR"
}

Log-Action "User Management Script Completed." "INFO"
Start-Sleep -Seconds 5
