# CyberPatriot Automation Master Launcher
# Purpose: Download tasks and launch them in parallel
# Author: Antigravity
# Version: 1.0

# ==========================================
# PRE-FLIGHT CHECKS
# ==========================================

# 1. Admin Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 5
    Exit
}

# 2. Setup Logging
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$MasterLog = Join-Path $LogDir ("Master_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")

function Log-Master {
    param([string]$Message, [string]$Type="INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp][$Type] $Message"
    Add-Content -Path $MasterLog -Value $Entry
    if ($Type -eq "ERROR") { Write-Host $Entry -ForegroundColor Red }
    elseif ($Type -eq "SUCCESS") { Write-Host $Entry -ForegroundColor Green }
    elseif ($Type -eq "WARNING") { Write-Host $Entry -ForegroundColor Yellow }
    else { Write-Host $Entry -ForegroundColor Cyan }
}

Log-Master "Master Launcher Started."

# ==========================================
# CONFIGURATION
# ==========================================

$ScriptBaseUrl = "https://raw.githubusercontent.com/ShamWuo/CYpatscript/main/scripts"
$LocalScriptDir = Join-Path $PSScriptRoot "scripts"

# Define Tasks
# In a real scenario, these URLs would be valid.
$Tasks = @(
    @{ Name="UserManagement"; Script="users.ps1"; Description="Removes unauthorized users"; Url="$ScriptBaseUrl/users.ps1" },
    @{ Name="PasswordPolicy"; Script="passwords.ps1"; Description="Enforces password security"; Url="$ScriptBaseUrl/passwords.ps1" },
    @{ Name="ServicesFirewall"; Script="services.ps1"; Description="Secures services and firewall"; Url="$ScriptBaseUrl/services.ps1" },
    @{ Name="AuditPolicy"; Script="audit.ps1"; Description="Enables audit logging"; Url="$ScriptBaseUrl/audit.ps1" },
    @{ Name="ProhibitedScanner"; Script="prohibited.ps1"; Description="Scans for banned files"; Url="$ScriptBaseUrl/prohibited.ps1" },
    @{ Name="WindowsUpdates"; Script="updates.ps1"; Description="Configures updates and Defender"; Url="$ScriptBaseUrl/updates.ps1" },
    @{ Name="BrowserSecurity"; Script="browsers.ps1"; Description="Secures Chrome and Firefox"; Url="$ScriptBaseUrl/browsers.ps1" },
    @{ Name="WindowsFeatures"; Script="features.ps1"; Description="Disables unsafe features (SMBv1, Telnet)"; Url="$ScriptBaseUrl/features.ps1" },
    @{ Name="NetworkShares"; Script="shares.ps1"; Description="Removes unauthorized shares"; Url="$ScriptBaseUrl/shares.ps1" }
)

# ==========================================
# DOWNLOAD PHASE
# ==========================================

if (!(Test-Path $LocalScriptDir)) {
    New-Item -ItemType Directory -Force -Path $LocalScriptDir | Out-Null
}

Log-Master "Starting Download Phase..."

foreach ($Task in $Tasks) {
    $LocalPath = Join-Path $LocalScriptDir $Task.Script
    
    # Try Download
    try {
        # Check connectivity first (simple ping)
        # Note: Github might be blocked in some schools, so strictly relying on download is risky. 
        # We try, if fail, check local.
        
        Log-Master "Attempting to download $($Task.Name)..."
        # Using Invoke-WebRequest
        Invoke-WebRequest -Uri $Task.Url -OutFile $LocalPath -ErrorAction Stop

        Log-Master "Downloaded $($Task.Name) successfully." "SUCCESS"
    } catch {
        Log-Master "Download failed for $($Task.Name) (Expected if offline/no repo). Checking local cache..." "WARNING"
        
        if (Test-Path $LocalPath) {
            Log-Master "Found local copy of $($Task.Name). Using cached version." "SUCCESS"
        } else {
            Log-Master "CRITICAL: Script $($Task.Name) not found locally or remotely!" "ERROR"
            # We continue, but this task will fail to launch
        }
    }
}

# ==========================================
# EXECUTION PHASE
# ==========================================

Log-Master "Starting Parallel Execution Phase..."
Start-Sleep -Seconds 2

foreach ($Task in $Tasks) {
    $LocalPath = Join-Path $LocalScriptDir $Task.Script
    
    if (Test-Path $LocalPath) {
        try {
            Log-Master "Launching $($Task.Name)..."
            
            # Use Start-Process to launch new window
            # -NoExit keeps window open so user can see output
            Start-Process -FilePath "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -File `"$LocalPath`"" `
                -Verb RunAs `
                -WindowStyle Normal
            
            # Stagger to prevent CPU spike / race conditions
            Start-Sleep -Milliseconds 800
            
        } catch {
            Log-Master "Failed to launch $($Task.Name): $_" "ERROR"
        }
    } else {
        Log-Master "Skipping $($Task.Name) - Script missing." "ERROR"
    }
}

Log-Master "All tasks launched." "SUCCESS"
Write-Host "`n========================================================" -ForegroundColor White
Write-Host "  Review spawned windows for progress." -ForegroundColor White
Write-Host "  Logs are being written to: $LogDir" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor White
Write-Host "Press any key to exit Master Launcher..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
