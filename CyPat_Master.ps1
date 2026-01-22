# CyberPatriot Automation Master Launcher
# Purpose: Download tasks and launch them in parallel with robust logging and management
# Author: Antigravity
# Version: 2.0

param(
    [switch]$DryRun,
    [string[]]$OnlyTasks  # e.g., -OnlyTasks "UserManagement","PasswordPolicy"
)

# ==========================================
# PRE-FLIGHT CHECKS
# ==========================================

# 1. Admin Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 5
    Exit
}

# 2. TLS 1.2 Security Protocol (Critical for GitHub)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 3. Setup Logging
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

Log-Master "Master Launcher v2.0 Started."

# ==========================================
# CONFIGURATION
# ==========================================

$ScriptBaseUrl = "https://raw.githubusercontent.com/ShamWuo/CYpatscript/main/scripts"
$LocalScriptDir = Join-Path $PSScriptRoot "scripts"

# Load Config if exists
$ConfigPath = Join-Path $PSScriptRoot "config\config.json"
if (Test-Path $ConfigPath) {
    Log-Master "Loading configuration from config.json..."
    try {
        $Config = Get-Content $ConfigPath | ConvertFrom-Json
        if ($Config.ScriptBaseUrl) { $ScriptBaseUrl = $Config.ScriptBaseUrl }
    } catch {
        Log-Master "Failed to load config.json - using defaults" "WARNING"
    }
}

# Define Tasks
$Tasks = @(
    @{ Name="UserManagement"; Script="users.ps1"; Description="Removes unauthorized users"; Url="$ScriptBaseUrl/users.ps1" },
    @{ Name="PasswordPolicy"; Script="passwords.ps1"; Description="Enforces password security"; Url="$ScriptBaseUrl/passwords.ps1" },
    @{ Name="ServicesFirewall"; Script="services.ps1"; Description="Secures services and firewall"; Url="$ScriptBaseUrl/services.ps1" },
    @{ Name="AuditPolicy"; Script="audit.ps1"; Description="Enables audit logging"; Url="$ScriptBaseUrl/audit.ps1" },
    @{ Name="ProhibitedScanner"; Script="prohibited.ps1"; Description="Scans for banned files"; Url="$ScriptBaseUrl/prohibited.ps1" },
    @{ Name="WindowsUpdates"; Script="updates.ps1"; Description="Configures updates and Defender"; Url="$ScriptBaseUrl/updates.ps1" },
    @{ Name="BrowserSecurity"; Script="browsers.ps1"; Description="Secures Chrome and Firefox"; Url="$ScriptBaseUrl/browsers.ps1" },
    @{ Name="WindowsFeatures"; Script="features.ps1"; Description="Disables unsafe features (SMBv1, Telnet)"; Url="$ScriptBaseUrl/features.ps1" },
    @{ Name="NetworkShares"; Script="shares.ps1"; Description="Removes unauthorized shares"; Url="$ScriptBaseUrl/shares.ps1" },
    @{ Name="SoftwareMgmt"; Script="software.ps1"; Description="Removes prohibited software (Wireshark, etc.)"; Url="$ScriptBaseUrl/software.ps1" },
    @{ Name="ScheduledTasks"; Script="tasks.ps1"; Description="Removes suspicious scheduled tasks"; Url="$ScriptBaseUrl/tasks.ps1" },
    @{ Name="StartupApps"; Script="startup.ps1"; Description="Cleans startup registry and folder"; Url="$ScriptBaseUrl/startup.ps1" },
    @{ Name="AdvSecurityPol"; Script="advanced_policy.ps1"; Description="Enforces User Rights & Security Options"; Url="$ScriptBaseUrl/advanced_policy.ps1" },
    @{ Name="RegistryHarden"; Script="registry.ps1"; Description="Disables LMHash, AutoRun, etc."; Url="$ScriptBaseUrl/registry.ps1" }
)

# Filter Tasks if -OnlyTasks is specified
if ($OnlyTasks) {
    Log-Master "Filtering tasks: $OnlyTasks" "INFO"
}

# ==========================================
# DOWNLOAD PHASE
# ==========================================

if (!(Test-Path $LocalScriptDir)) {
    New-Item -ItemType Directory -Force -Path $LocalScriptDir | Out-Null
}

Log-Master "Checking internet connectivity..."
try {
    $null = Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Log-Master "Internet connection confirmed." "SUCCESS"
    $IsOnline = $true
} catch {
    Log-Master "No internet connection - will use local scripts only." "WARNING"
    $IsOnline = $false
}

if ($IsOnline) {
    Log-Master "Starting Download Phase..."
    foreach ($Task in $Tasks) {
        if ($OnlyTasks -and $Task.Name -notin $OnlyTasks) { continue }

        $LocalPath = Join-Path $LocalScriptDir $Task.Script
        
        try {
            Log-Master "Downloading $($Task.Name)..."
            Invoke-WebRequest -Uri $Task.Url -OutFile $LocalPath -UseBasicParsing -ErrorAction Stop
            Log-Master "Downloaded $($Task.Name) successfully." "SUCCESS"
        } catch {
            Log-Master "Download failed for $($Task.Name): $_" "WARNING"
        }
    }
}

# ==========================================
# VISUAL FEEDBACK & EXECUTION
# ==========================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Tasks Ready to Launch:" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
foreach ($Task in $Tasks) {
    if ($OnlyTasks -and $Task.Name -notin $OnlyTasks) { continue }

    if (Test-Path (Join-Path $LocalScriptDir $Task.Script)) {
        Write-Host "  ✓ $($Task.Name) - $($Task.Description)" -ForegroundColor White
    } else {
        Write-Host "  ✗ $($Task.Name) - MISSING" -ForegroundColor Red
    }
}
Write-Host ""

Log-Master "Starting Parallel Execution Phase..."
Start-Sleep -Seconds 2

foreach ($Task in $Tasks) {
    if ($OnlyTasks -and $Task.Name -notin $OnlyTasks) { 
        Log-Master "Skipping $($Task.Name) (not selected)" "INFO"
        continue 
    }

    $LocalPath = Join-Path $LocalScriptDir $Task.Script
    
    if (Test-Path $LocalPath) {
        
        if ($DryRun) {
            Log-Master "[DRY RUN] Would launch $($Task.Name)" "WARNING"
            continue
        }

        # Create a wrapper that handles logging and window title
        $WrapperPath = Join-Path $LocalScriptDir "wrapper_$($Task.Script)"
        $WrapperContent = @"
`$Host.UI.RawUI.WindowTitle = "CyberPatriot - $($Task.Name)"
`$TaskLog = Join-Path "$LogDir" "$($Task.Name)_`$(Get-Date -Format 'HHmmss').txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "$($Task.Name)" -ForegroundColor Green
Write-Host "$($Task.Description)" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

"[$($Task.Name)] Started at `$(Get-Date)" | Out-File `$TaskLog

try {
    & "$LocalPath" 2>&1 | Tee-Object -FilePath `$TaskLog -Append
    "`n[$($Task.Name)] Completed at `$(Get-Date)" | Out-File `$TaskLog -Append
    Write-Host "`n[SUCCESS] Task completed!" -ForegroundColor Green
} catch {
    "`n[$($Task.Name)] ERROR: `$_" | Out-File `$TaskLog -Append
    Write-Host "`n[ERROR] `$_" -ForegroundColor Red
}

Write-Host "`nLog: `$TaskLog" -ForegroundColor Cyan
Read-Host "`nPress Enter to close"
"@
        $WrapperContent | Out-File $WrapperPath -Force

        try {
            Log-Master "Launching $($Task.Name)..."
            
            # Use Start-Process with -NoExit and Wrapper
            Start-Process -FilePath "powershell.exe" `
                -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-File `"$WrapperPath`"" `
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

# ==========================================
# COMPLETION SUMMARY
# ==========================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Execution Summary:" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Master Log: $MasterLog" -ForegroundColor White
Write-Host "  Task Logs: $LogDir\*.txt" -ForegroundColor White
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Monitor spawned windows" -ForegroundColor White
Write-Host "  2. Review logs for errors" -ForegroundColor White
Write-Host "  3. Reboot when all complete" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

Log-Master "Master Launcher sequence completed." "SUCCESS"
Write-Host "Press any key to exit Master Launcher..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
