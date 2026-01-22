# CyberPatriot Scheduled Tasks Management
# Purpose: Detect and remove malicious scheduled tasks
# Author: Antigravity
# Version: 1.0

# Logging Setup
$LogDir = "C:\CyPat_Logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("Tasks_" + (Get-Date -Format "HHmmss") + ".txt")

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

Log-Action "Starting Scheduled Task Scan" "INFO"

# Keywords to look for in Task Actions
$SuspiciousKeywords = @(
    "nc.exe",
    "ncat.exe",
    "netcat",
    "cmd.exe", # Context dependent, but often bad if alone or in temp
    "powershell.exe", # Context dependent
    "javascript:",
    "rundll32",
    "regsvr32",
    "Appdata",
    "Temp"
)

try {
    $AllTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue
    # Also check typical malware locations if possible, but root is good start
    
    foreach ($Task in $AllTasks) {
        # Inspect Actions
        try {
            # Some actions are COM objects, we focus on Executable
            $Actions = $Task.Actions
            foreach ($Action in $Actions) {
                if ($Action.Execute) {
                    $ExecStr = $Action.Execute + " " + $Action.Arguments
                    
                    foreach ($Keyword in $SuspiciousKeywords) {
                        if ($ExecStr -like "*$Keyword*") {
                            # Verify if it's legit MS task first
                            # For competition, non-MS tasks in root are usually suspect
                            if ($Task.Author -notlike "*Microsoft*" -and $Task.TaskPath -eq "\") {
                                Log-Action "Suspicious Task Found: [$($Task.TaskName)] Command: $ExecStr" "WARNING"
                                
                                # In strict scoring, unsafe to auto-delete unless sure.
                                # Check logic: Netcat is always bad.
                                if ($ExecStr -like "*nc.exe*" -or $ExecStr -like "*netcat*" -or $ExecStr -like "*ncat*") {
                                    Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction Stop
                                    Log-Action "Removed Malicious Task: $($Task.TaskName)" "SUCCESS"
                                } else {
                                     Log-Action "Manual Review Required for: $($Task.TaskName)" "WARNING"
                                }
                            }
                        }
                    }
                }
            }
        } catch {
             # Ignore empty actions
        }
    }

} catch {
    Log-Action "Error scanning tasks: $_" "ERROR"
}

Log-Action "Scheduled Task Audit Completed." "INFO"
Start-Sleep -Seconds 5
