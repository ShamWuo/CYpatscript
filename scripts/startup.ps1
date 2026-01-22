# CyberPatriot Startup Programs Management
# Purpose: Clean Run keys and Startup folder
# Author: Antigravity
# Version: 1.0

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Startup_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Startup Program Audit" "INFO"

# Registry Paths
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

# Known Suspicious Keywords
$Suspicious = @("nc.exe", "netcat", "shutdown", "powershell", "cmd.exe", "script", "hack")

foreach ($Path in $RegPaths) {
    if (Test-Path $Path) {
        try {
            $Properties = Get-ItemProperty -Path $Path
            foreach ($Prop in $Properties.PSObject.Properties) {
                # Skip system properties
                if ($Prop.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) { continue }
                
                $Value = $Prop.Value
                Log-Action "Checking Startup Item: [$($Prop.Name)] => $Value" "INFO"
                
                foreach ($Bad in $Suspicious) {
                    if ("$Value" -like "*$Bad*") {
                        Log-Action "Removing Suspicious Startup Item: $($Prop.Name)" "WARNING"
                        Remove-ItemProperty -Path $Path -Name $Prop.Name -ErrorAction Stop
                        Log-Action "Removed $($Prop.Name)" "SUCCESS"
                        break 
                    }
                }
            }
        } catch {
            Log-Action "Error reading path $Path : $_" "ERROR"
        }
    }
}

# Startup Folder Common Path
$StartupPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $StartupPath) {
    Log-Action "Checking Global Startup Folder..." "INFO"
    $Files = Get-ChildItem -Path $StartupPath
    foreach ($File in $Files) {
        # CyPat usually puts bad bat/exe files here
        if ($File.Extension -in @(".bat", ".exe", ".vbs", ".ps1")) {
            Log-Action "Suspicious file in Startup: $($File.Name)" "WARNING"
            # Move to safety instead of delete? Or Delete? "Remove" usually implies delete.
            # Safe DELETE
            Remove-Item -Path $File.FullName -Force
            Log-Action "Deleted $($File.Name)" "SUCCESS"
        }
    }
}

Log-Action "Startup Audit Completed." "INFO"
Start-Sleep -Seconds 5
