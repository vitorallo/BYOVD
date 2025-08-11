# NVIDIA Driver Setup - PowerShell Component
# Complete BYOVD Attack Simulation Package
# Part of the Lazarus Group ClickFake simulation
# Author: Crimson7 Threat Intelligence Team

param(
    [switch]$SilentInstall = $false,
    [switch]$SkipChecks = $false,
    [switch]$SimulationMode = $true,
    [string]$InstallPath = $PSScriptRoot
)

# Global configuration
$Global:LogFile = "$env:TEMP\nvidia_powershell_setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Global:DriverFile = Join-Path $InstallPath "iqvw64.sys"
$Global:VBSLoader = Join-Path $InstallPath "driver_loader.vbs"

function Write-SetupLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (-not $SilentInstall) {
        Write-Host $logEntry -ForegroundColor $(
            switch ($Level) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "STAGE" { "Cyan" }
                default { "White" }
            }
        )
    }
    
    Add-Content -Path $Global:LogFile -Value $logEntry
}

function Show-NVIDIABanner {
    if (-not $SilentInstall) {
        Clear-Host
        Write-Host @"
                                                                    
    ███╗   ██╗██╗   ██╗██╗██████╗ ██╗ █████╗                       
    ████╗  ██║██║   ██║██║██╔══██╗██║██╔══██╗                      
    ██╔██╗ ██║██║   ██║██║██║  ██║██║███████║                      
    ██║╚██╗██║╚██╗ ██╔╝██║██║  ██║██║██╔══██║                      
    ██║ ╚████║ ╚████╔╝ ██║██████╔╝██║██║  ██║                      
    ╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝                      
                                                                    
    Driver Update Package v496.13 - Advanced Installation System
    BYOVD Attack Simulation - Crimson7 Research
                                                                    
"@ -ForegroundColor Green
        
        Write-Host "Initializing NVIDIA Driver Installation System..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

function Test-SystemRequirements {
    Write-SetupLog "Checking system requirements..." -Level "STAGE"
    
    # Check OS version
    $osVersion = [Environment]::OSVersion.Version
    Write-SetupLog "Operating System: $([Environment]::OSVersion.VersionString)"
    
    if ($osVersion.Major -lt 10) {
        Write-SetupLog "WARNING: Windows 10 or later recommended" -Level "WARNING"
    }
    
    # Check architecture
    $arch = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    Write-SetupLog "System Architecture: $arch"
    
    if ($arch -ne "AMD64") {
        Write-SetupLog "WARNING: x64 architecture recommended" -Level "WARNING"
    }
    
    # Check PowerShell version
    Write-SetupLog "PowerShell Version: $($PSVersionTable.PSVersion)"
    
    # Check execution policy
    $execPolicy = Get-ExecutionPolicy
    Write-SetupLog "Execution Policy: $execPolicy"
    
    if ($execPolicy -eq "Restricted") {
        Write-SetupLog "WARNING: Restrictive execution policy detected" -Level "WARNING"
    }
    
    # Check available disk space
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    Write-SetupLog "Available Disk Space: $freeSpaceGB GB"
    
    if ($freeSpaceGB -lt 2) {
        Write-SetupLog "WARNING: Low disk space detected" -Level "WARNING"
    }
    
    Write-SetupLog "System requirements check completed" -Level "SUCCESS"
    return $true
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Write-SetupLog "Administrative privileges: $(if($isAdmin){'Available'}else{'Not available'})"
    
    if (-not $isAdmin) {
        Write-SetupLog "Some installation features require administrative privileges" -Level "WARNING"
    }
    
    return $isAdmin
}

function Invoke-DriverPreparation {
    Write-SetupLog "Preparing driver components..." -Level "STAGE"
    
    # Check for driver file
    if (Test-Path $Global:DriverFile) {
        $driverInfo = Get-Item $Global:DriverFile
        Write-SetupLog "Driver file found: $($driverInfo.Name) ($($driverInfo.Length) bytes)"
        
        # Calculate hash
        $hash = Get-FileHash $Global:DriverFile -Algorithm SHA256
        Write-SetupLog "Driver SHA256: $($hash.Hash)"
        
        # Simulate digital signature check
        Write-SetupLog "Verifying digital signature..."
        Start-Sleep -Seconds 1
        Write-SetupLog "Digital signature: Valid (Simulated)" -Level "SUCCESS"
        
    } else {
        Write-SetupLog "Driver file not found - creating mock driver" -Level "WARNING"
        New-MockDriver -Path $Global:DriverFile
    }
    
    # Check VBS loader
    if (Test-Path $Global:VBSLoader) {
        Write-SetupLog "VBS loader found: $(Split-Path $Global:VBSLoader -Leaf)"
    } else {
        Write-SetupLog "VBS loader not found - using PowerShell-only installation" -Level "WARNING"
    }
    
    Write-SetupLog "Driver preparation completed" -Level "SUCCESS"
}

function New-MockDriver {
    param([string]$Path)
    
    Write-SetupLog "Creating mock vulnerable driver..."
    
    $driverContent = @"
MOCK NVIDIA/INTEL VULNERABLE DRIVER
===================================
File: iqvw64.sys (Intel Ethernet Diagnostics Driver)
CVE: CVE-2015-2291 (Write-What-Where Vulnerability)
Created: $(Get-Date)
Purpose: BYOVD Attack Simulation

VULNERABILITY SIMULATION:
This mock driver simulates the vulnerable Intel Ethernet
diagnostics driver commonly exploited in BYOVD attacks.

ATTACK CAPABILITIES (Simulated):
- Arbitrary kernel memory writes
- Privilege escalation to SYSTEM
- Security software bypass
- Rootkit installation support
- Driver signature enforcement bypass

THREAT ACTORS USING THIS TECHNIQUE:
- SCATTERED SPIDER (UNC3944)
- Medusa Ransomware operators
- Lazarus Group
- Various APT groups

MITRE ATT&CK MAPPING:
- T1068: Exploitation for Privilege Escalation
- T1562.001: Impair Defenses
- T1014: Rootkit
- T1553.005: Subvert Trust Controls

WARNING: This is a harmless simulation file for testing purposes only!
"@
    
    Set-Content -Path $Path -Value $driverContent
    Write-SetupLog "Mock driver created: $Path"
}

function Invoke-DriverInstallation {
    Write-SetupLog "Beginning driver installation process..." -Level "STAGE"
    
    $isAdmin = Test-AdminPrivileges
    
    if ($isAdmin) {
        # Simulate service-based installation
        Write-SetupLog "Installing driver as kernel service..."
        
        $serviceName = "NVIDIAEthDiag"
        $serviceDisplayName = "NVIDIA Ethernet Diagnostics Service"
        
        try {
            # Create the service (simulation)
            Write-SetupLog "Creating service: $serviceName"
            $createArgs = @("create", $serviceName, "binPath=", "`"$Global:DriverFile`"", "type=", "kernel", "start=", "demand", "DisplayName=", "`"$serviceDisplayName`"")
            
            if ($SimulationMode) {
                Write-SetupLog "SIMULATION: sc.exe $($createArgs -join ' ')"
                Write-SetupLog "Service creation simulated successfully" -Level "SUCCESS"
            } else {
                $result = Start-Process -FilePath "sc.exe" -ArgumentList $createArgs -Wait -PassThru -NoNewWindow
                if ($result.ExitCode -eq 0) {
                    Write-SetupLog "Service created successfully" -Level "SUCCESS"
                    
                    # Attempt to start the service
                    Write-SetupLog "Starting driver service..."
                    $startResult = Start-Process -FilePath "sc.exe" -ArgumentList "start", $serviceName -Wait -PassThru -NoNewWindow
                    
                    if ($startResult.ExitCode -eq 0) {
                        Write-SetupLog "Driver loaded successfully - BYOVD attack vector established!" -Level "SUCCESS"
                    } else {
                        Write-SetupLog "Driver start failed (expected with mock driver)" -Level "WARNING"
                    }
                    
                    # Cleanup test service
                    Start-Process -FilePath "sc.exe" -ArgumentList "stop", $serviceName -Wait -NoNewWindow | Out-Null
                    Start-Process -FilePath "sc.exe" -ArgumentList "delete", $serviceName -Wait -NoNewWindow | Out-Null
                    Write-SetupLog "Test service cleaned up"
                } else {
                    Write-SetupLog "Service creation failed" -Level "ERROR"
                }
            }
        } catch {
            Write-SetupLog "Driver installation error: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-SetupLog "Administrative privileges required for driver installation" -Level "WARNING"
        Write-SetupLog "Simulating user-mode installation alternative..."
        
        # Simulate user-mode installation
        Invoke-UserModeInstallation
    }
}

function Invoke-UserModeInstallation {
    Write-SetupLog "Executing user-mode installation simulation..."
    
    # Simulate VBS loader execution
    if (Test-Path $Global:VBSLoader) {
        Write-SetupLog "Launching VBS driver loader..."
        
        try {
            if ($SimulationMode) {
                Write-SetupLog "SIMULATION: wscript.exe `"$Global:VBSLoader`""
                Start-Sleep -Seconds 2
                Write-SetupLog "VBS loader execution simulated" -Level "SUCCESS"
            } else {
                Start-Process -FilePath "wscript.exe" -ArgumentList "`"$Global:VBSLoader`"" -WindowStyle Hidden -Wait
                Write-SetupLog "VBS loader executed" -Level "SUCCESS"
            }
        } catch {
            Write-SetupLog "VBS loader execution failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    # Simulate alternative privilege escalation
    Write-SetupLog "Attempting alternative privilege escalation methods..."
    Write-SetupLog "- UAC bypass techniques"
    Write-SetupLog "- Token manipulation"
    Write-SetupLog "- Exploit chain execution"
}

function Invoke-PostInstallation {
    Write-SetupLog "Executing post-installation procedures..." -Level "STAGE"
    
    # Create persistence mechanisms
    New-PersistenceMechanisms
    
    # Simulate defense evasion
    Invoke-DefenseEvasion
    
    # Create installation artifacts
    New-InstallationArtifacts
    
    # Simulate cleanup
    Invoke-InstallationCleanup
    
    Write-SetupLog "Post-installation completed" -Level "SUCCESS"
}

function New-PersistenceMechanisms {
    Write-SetupLog "Establishing persistence mechanisms..."
    
    # Registry persistence
    try {
        $regPath = "HKCU:\Software\NVIDIA Corporation\Installer"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "Version" -Value "496.13"
        Set-ItemProperty -Path $regPath -Name "InstallDate" -Value (Get-Date)
        Set-ItemProperty -Path $regPath -Name "ComponentType" -Value "Driver"
        
        # BYOVD test entries
        $testRegPath = "HKCU:\Software\BYOVDNVIDIASetup"
        if (-not (Test-Path $testRegPath)) {
            New-Item -Path $testRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $testRegPath -Name "InstallationID" -Value (New-Guid).ToString()
        Set-ItemProperty -Path $testRegPath -Name "SimulationMode" -Value $SimulationMode
        Set-ItemProperty -Path $testRegPath -Name "AttackChain" -Value "Curl->PowerShell->VBS->Driver"
        
        Write-SetupLog "Registry persistence established" -Level "SUCCESS"
    } catch {
        Write-SetupLog "Registry persistence failed: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Scheduled task persistence (simulation)
    Write-SetupLog "Creating scheduled maintenance tasks..."
    Write-SetupLog "- NVIDIA Update Checker (weekly)"
    Write-SetupLog "- Driver Health Monitor (daily)"
    Write-SetupLog "- System Compatibility Scan (monthly)"
}

function Invoke-DefenseEvasion {
    Write-SetupLog "Implementing defense evasion techniques..."
    
    # Simulate process injection
    Write-SetupLog "- Process injection simulation"
    
    # Simulate anti-analysis
    Write-SetupLog "- Anti-debugging measures"
    Write-SetupLog "- Sandbox detection bypass"
    Write-SetupLog "- VM detection evasion"
    
    # Simulate ETW disruption
    Write-SetupLog "- ETW provider disruption"
    
    # Simulate rootkit deployment
    Write-SetupLog "- Kernel-level rootkit deployment"
    Write-SetupLog "- File system filtering installation"
    Write-SetupLog "- Process hiding capabilities enabled"
}

function New-InstallationArtifacts {
    Write-SetupLog "Creating installation completion artifacts..."
    
    # Installation summary
    $summaryPath = "$env:TEMP\nvidia_installation_summary.txt"
    $summaryContent = @"
NVIDIA Driver Installation Summary
=================================
Installation Date: $(Get-Date)
Package Version: 496.13 WHQL
Installation Mode: $(if($SilentInstall){'Silent'}else{'Interactive'})
Administrative Privileges: $(Test-AdminPrivileges)
Simulation Mode: $SimulationMode

Components Installed:
- Intel Ethernet Diagnostics Driver (iqvw64.sys)
- NVIDIA Display Driver Components
- Registry Configuration Entries  
- Persistence Mechanisms
- Defense Evasion Modules

BYOVD Attack Chain Simulation:
1. Initial Access: Fake driver update social engineering
2. Execution: Multi-stage PowerShell and VBS execution
3. Privilege Escalation: Vulnerable driver exploitation
4. Defense Evasion: Security software bypass
5. Persistence: Registry and scheduled task creation
6. Impact: Full kernel-level access achieved

MITRE ATT&CK Techniques Demonstrated:
- T1566.002: Phishing - Spearphishing Link
- T1105: Ingress Tool Transfer  
- T1059.001: PowerShell Execution
- T1059.005: VBS Execution
- T1068: Exploitation for Privilege Escalation
- T1562.001: Impair Defenses
- T1547.006: Kernel Modules and Extensions
- T1014: Rootkit

Installation Status: COMPLETED SUCCESSFULLY
Attack Simulation: FULLY OPERATIONAL
Detection Opportunities: Registry monitoring, file creation, service installation, VBS execution

Log Files:
- PowerShell Setup: $Global:LogFile
- VBS Installation: %TEMP%\driver_loader.log
- Main Installation: %TEMP%\nvidia_install_*.log

WARNING: This is a security research simulation - not a real malware infection
"@
    
    Set-Content -Path $summaryPath -Value $summaryContent
    Write-SetupLog "Installation summary created: $summaryPath"
    
    # Create IOC file for blue team
    $iocPath = "$env:TEMP\nvidia_byovd_iocs.txt"
    $iocContent = @"
BYOVD Attack Simulation - Indicators of Compromise (IOCs)
========================================================
Generated: $(Get-Date)

File System IOCs:
- $Global:DriverFile (Mock vulnerable driver)
- $Global:VBSLoader (VBS attack script)
- $summaryPath (Installation summary)
- %TEMP%\nvidia_*.log (Installation logs)
- %TEMP%\byovd_*.* (Test artifacts)

Registry IOCs:
- HKCU\Software\NVIDIA Corporation\Installer
- HKCU\Software\BYOVDNVIDIASetup
- HKLM\SYSTEM\CurrentControlSet\Services\NVIDIAEthDiag

Process IOCs:
- powershell.exe executing setup.ps1
- wscript.exe executing VBS files
- sc.exe creating kernel services
- curl.exe downloading driver packages

Network IOCs:
- DNS queries to smartdriverfix.cloud
- HTTPS downloads of nvidiadrivers.zip
- User-Agent: curl/* or PowerShell/*

Behavioral IOCs:
- Service creation for kernel drivers
- Registry modifications in NVIDIA paths
- VBS script execution from TEMP directories
- PowerShell execution with driver-related arguments
- File creation patterns matching driver packages

Detection Rules:
- Monitor for iqvw64.sys file creation
- Alert on VBS execution from TEMP
- Detect service creation with kernel type
- Monitor registry writes to NVIDIA paths
- Track PowerShell execution with setup.ps1
"@
    
    Set-Content -Path $iocPath -Value $iocContent
    Write-SetupLog "IOC file created for blue team: $iocPath"
}

function Invoke-InstallationCleanup {
    Write-SetupLog "Performing installation cleanup..."
    
    # Simulate log rotation
    Write-SetupLog "Rotating installation logs..."
    
    # Simulate temporary file cleanup
    Write-SetupLog "Cleaning temporary installation files..."
    
    # Simulate evidence removal (anti-forensics)
    Write-SetupLog "Implementing anti-forensics measures..."
    Write-SetupLog "- Timestamp manipulation"
    Write-SetupLog "- Free space wiping"
    Write-SetupLog "- Log entry modification"
    
    Write-SetupLog "Installation cleanup completed"
}

function Show-InstallationComplete {
    if (-not $SilentInstall) {
        Clear-Host
        Write-Host @"

    [+] NVIDIA Driver Installation Completed Successfully!
    
    Driver Version: 496.13 WHQL
    Installation Time: $(((Get-Date) - $script:StartTime).TotalSeconds) seconds
    Components: All components installed successfully
    
    Your system is now optimized with the latest NVIDIA drivers.
    
    BYOVD Attack Simulation Summary:
    - Complete attack chain executed successfully
    - All MITRE ATT&CK techniques demonstrated  
    - Detection opportunities documented
    - Blue team artifacts generated
    
    Thank you for using NVIDIA Driver Installer!
    
"@ -ForegroundColor Green
        
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Main execution
$script:StartTime = Get-Date

Write-SetupLog "=== NVIDIA Driver PowerShell Setup Started ===" -Level "STAGE"
Write-SetupLog "Installation Path: $InstallPath"
Write-SetupLog "Silent Install: $SilentInstall"
Write-SetupLog "Simulation Mode: $SimulationMode"

try {
    Show-NVIDIABanner
    
    if (-not $SkipChecks) {
        Test-SystemRequirements | Out-Null
    }
    
    Invoke-DriverPreparation
    Invoke-DriverInstallation
    Invoke-PostInstallation
    
    Show-InstallationComplete
    
    Write-SetupLog "=== NVIDIA Driver Installation Completed Successfully ===" -Level "SUCCESS"
    
} catch {
    Write-SetupLog "Installation failed: $($_.Exception.Message)" -Level "ERROR"
    Write-SetupLog "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    if (-not $SilentInstall) {
        Write-Host "`nInstallation failed. Check log file: $Global:LogFile" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
}

Write-SetupLog "PowerShell setup log: $Global:LogFile"