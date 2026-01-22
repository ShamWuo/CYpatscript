# CyberPatriot Automated Hardening System V1

## Project Overview
A comprehensive CyberPatriot competition automation tool that downloads hardening scripts from GitHub repositories and executes them in parallel PowerShell windows to maximize points efficiently.

## Core Features
*   **Master Launcher**: Orchestrates parallel execution of all hardening tasks.
*   **Modular Architecture**: 6 specialized modules for distinct security categories.
*   **Parallel Processing**: Maximizes point gain speed by running tasks simultaneously.
*   **Robust Logging**: Detailed logs for every action and decision.
*   **Safety First**: Pre-execution checks and careful error handling.

## Quick Start Guide

### Prerequisites
*   Windows 10 or Windows 11
*   PowerShell 5.1 (Default on Windows)
*   Administrator privileges
*   Internet connection (for downloading scripts)

### Installation
1.  Download or clone this repository to your target machine.
    ```powershell
    git clone https://github.com/YourUsername/cypat-automation.git
    ```
2.  Navigate to the directory.
    ```powershell
    cd cypat-automation
    ```

### How to Run
1.  **Edit Configuration**: Open `config/config.json` (or scripts directly if not using JSON config) to set authorized users and admins.
2.  **Launch Master Script**:
    Run the following command in an Administrator PowerShell window:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\CyPat_Master.ps1
    ```
3.  **Monitor Progress**: Watch the spawned windows as they execute their tasks.
4.  **Review Logs**: Check `C:\CyPat_Logs\` for detailed results.
5.  **Reboot**: It is recommended to reboot the system after completion to ensure all changes take effect.

## Configuration Guide

### Authorized Users
Edit the `config/config.json` file to specify which users should exist and which should be administrators.
```json
{
  "authorizedUsers": ["Administrator", "CyberPatriot", "Judge"],
  "authorizedAdmins": ["Administrator", "CyberPatriot"]
}
```
**Warning**: Any user NOT in `authorizedUsers` will be disabled or removed. Any user in `Administrators` group NOT in `authorizedAdmins` will be demoted.

### GitHub Integration
To use your own forks of the scripts, update the URL references in `CyPat_Master.ps1` or the configuration file.

## Task Descriptions

### 1. User Management (`users.ps1`)
*   Removes unauthorized users.
*   Fixes Administrator group membership.
*   Disables the Guest account.
*   **Points**: High value for removing unauthorized accounts.

### 2. Password Policy (`passwords.ps1`)
*   Enforces strong password requirements (Length=12, Age, Complexity, Lockout).
*   **Points**: Essential for almost every image.

### 3. Services & Firewall (`services.ps1`)
*   Enables Windows Firewall on all profiles.
*   Disables high-risk services (Telnet, FTP, Remote Registry, etc.).
*   **Points**: Critical for network security.

### 4. Audit Policy (`audit.ps1`)
*   Enables comprehensive auditing (Logon, Account Management, etc.).
*   Applies security registry tweaks (Disable LM Hash, Limit anonymous access).
*   **Points**: Often overlooked but valuable.

### 5. Prohibited Content (`prohibited.ps1`)
*   Scans common directories for media files (.mp3, .mp4, etc.) and hacking tools.
*   Lists potentially prohibited software.
*   **Note**: Does NOT auto-delete files to prevent accidental point loss. Review the logs `C:\CyPat_Logs\` and delete manually.

### 6. Windows Updates (`updates.ps1`)
*   Configures Windows Update to auto-install.
*   Updates Windows Defender definitions.
*   **Points**: Standard requirement for all images.

### 7. Browser Security (`browsers.ps1`)
*   **Firefox**: Enforces strict policies (No popups, no telemetry, auto-updates).
*   **Chrome**: Sets registry policies for SafeBrowsing and blocking 3rd party cookies.
*   **Points**: Critical for browser-related checklists.

### 8. Windows Features (`features.ps1`)
*   Disables **SMBv1** (Legacy protocol/WannaCry vector).
*   Disables Telnet Client/Server and TFTP.
*   **Points**: Often hidden high-value points.

### 9. Network Shares (`shares.ps1`)
*   Disables **Remote Desktop (RDP)** connection.
*   Removes unauthorized network shares (anything not C$, ADMIN$, IPC$, etc.).
*   **Points**: Essential for reducing attack surface.

## Troubleshooting

### "Execution of scripts is disabled on this system"
Run this command before the script:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Script window closes immediately
Check the logs in `C:\CyPat_Logs\`. If no log exists, the script likely failed to start—try running it manually to see the error execution.

### Network Errors
Ensure you have internet access. If offline, ensure you have the `scripts/` folder populated locally.

## Safety Warnings
> [!IMPORTANT]
> **ALWAYS READ THE COMPETITION README FIRST.**
> If the README says "Do not remove user X", ensure you add them to your `authorizedUsers` list!

> [!CAUTION]
> **Use at your own risk.** Automated hardening can sometimes break necessary services or lock you out if misconfigured. Always test in a VM first.

> [!TIP]
> **Backup often.** Create a VM snapshot before running this tool.

> [!TIP]
> **Quick Launch**
>Set-ExecutionPolicy Bypass -Scope Process -Force; iwr "https://raw.githubusercontent.com/ShamWuo/CYpatscript/main/CyPat_Master.ps1" -OutFile "CyPat_Master.ps1"; .\CyPat_Master.ps1