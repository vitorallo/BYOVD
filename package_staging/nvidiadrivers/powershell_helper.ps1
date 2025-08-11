# BYOVD PowerShell Helper Script
# Works in conjunction with VBS loaders for complete attack simulation
# Author: Crimson7 Threat Intelligence Team

param(
    [string]$Action = "PrepareEnvironment",
    [string]$DriverPath = "$env:TEMP\nvidiadrivers\test_driver.sys",
    [switch]$CleanupOnly = $false,
    [switch]$VerboseLogging = $false
)

# Global variables
$script:LogFile = "$env:TEMP\byovd_powershell_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:TempDir = "$env:TEMP\nvidiadrivers"

function Write-BYOVDLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($VerboseLogging) {
        Write-Host $logEntry -ForegroundColor $(
            switch ($Level) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                default { "White" }
            }
        )
    }
    
    Add-Content -Path $script:LogFile -Value $logEntry
}

function Test-AdminPrivileges {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function New-MockVulnerableDriver {
    param([string]$Path)
    
    Write-BYOVDLog "Creating mock vulnerable driver at: $Path"
    
    # Ensure directory exists
    $parentDir = Split-Path $Path -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        Write-BYOVDLog "Created directory: $parentDir"
    }
    
    # Create driver content that simulates a vulnerable driver
    $driverHeader = @"
MOCK_VULNERABLE_DRIVER_SIMULATION
==================================
Driver Name: Intel Ethernet Diagnostics Driver (Simulated)
CVE: CVE-2015-2291 (Simulated)
Original: iqvw64.sys
Purpose: BYOVD Testing and Simulation
Created: $(Get-Date)
Size: Padded to realistic size

VULNERABILITY SIMULATION:
This mock driver simulates the write-what-where vulnerability
commonly exploited in BYOVD attacks. In a real scenario, this
would allow arbitrary kernel memory writes.

ATTACK TECHNIQUES SIMULATED:
- T1068: Exploitation for Privilege Escalation
- T1562.001: Disable or Modify Tools
- T1014: Rootkit capabilities
- T1553.005: Driver Signature Enforcement Bypass

"@
    
    # Add padding to make it look more realistic
    $padding = "X" * 2048
    $driverContent = $driverHeader + "`n" + $padding
    
    try {
        Set-Content -Path $Path -Value $driverContent -Force
        Write-BYOVDLog "Mock driver created successfully" -Level "SUCCESS"
        Write-BYOVDLog "Driver size: $((Get-Item $Path).Length) bytes"
        return $true
    }
    catch {
        Write-BYOVDLog "Failed to create mock driver: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-DriverInstallationSimulation {
    param([string]$DriverPath, [string]$ServiceName = "BYOVDTestService")
    
    Write-BYOVDLog "Starting driver installation simulation"
    
    if (-not (Test-Path $DriverPath)) {
        Write-BYOVDLog "Driver file not found, creating mock driver..." -Level "WARNING"
        if (-not (New-MockVulnerableDriver -Path $DriverPath)) {
            return $false
        }
    }
    
    $isAdmin = Test-AdminPrivileges
    Write-BYOVDLog "Running as administrator: $isAdmin"
    
    if ($isAdmin) {
        try {
            # Create the service
            Write-BYOVDLog "Creating driver service: $ServiceName"
            $createResult = Start-Process -FilePath "sc.exe" -ArgumentList "create", $ServiceName, "binPath=", "`"$DriverPath`"", "type=", "kernel", "start=", "demand" -Wait -PassThru -NoNewWindow
            
            if ($createResult.ExitCode -eq 0) {
                Write-BYOVDLog "Service created successfully" -Level "SUCCESS"
                
                # Attempt to start the service (will fail with mock driver)
                Write-BYOVDLog "Attempting to start driver service..."
                $startResult = Start-Process -FilePath "sc.exe" -ArgumentList "start", $ServiceName -Wait -PassThru -NoNewWindow
                
                if ($startResult.ExitCode -eq 0) {
                    Write-BYOVDLog "Driver loaded successfully - BYOVD simulation successful!" -Level "SUCCESS"
                } else {
                    Write-BYOVDLog "Driver start failed (expected with mock driver) - Exit code: $($startResult.ExitCode)" -Level "WARNING"
                    Write-BYOVDLog "In real attack, kernel access would now be available"
                }
                
                # Cleanup
                Start-Process -FilePath "sc.exe" -ArgumentList "stop", $ServiceName -Wait -NoNewWindow | Out-Null
                Start-Process -FilePath "sc.exe" -ArgumentList "delete", $ServiceName -Wait -NoNewWindow | Out-Null
                Write-BYOVDLog "Test service cleaned up"
                
                return $true
            } else {
                Write-BYOVDLog "Service creation failed - Exit code: $($createResult.ExitCode)" -Level "ERROR"
                return $false
            }
        }
        catch {
            Write-BYOVDLog "Driver installation failed: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    } else {
        Write-BYOVDLog "Administrative privileges required for driver installation" -Level "WARNING"
        Write-BYOVDLog "Simulating driver installation without actual system modification"
        return $true
    }
}

function Invoke-PostExploitationSimulation {
    Write-BYOVDLog "Starting post-exploitation simulation"
    
    # Simulate security process enumeration
    Write-BYOVDLog "Enumerating security processes..."
    $securityProcesses = @("MsMpEng", "CSAgent", "XDRAgent", "SentinelAgent", "cyserver")
    foreach ($proc in $securityProcesses) {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($processes) {
            Write-BYOVDLog "Security process found: $proc (PIDs: $($processes.Id -join ', '))"
        } else {
            Write-BYOVDLog "Security process not found: $proc"
        }
    }
    
    # Simulate registry modifications
    Write-BYOVDLog "Simulating registry modifications for persistence..."
    try {
        $regPath = "HKCU:\Software\BYOVDTest"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "InstallDate" -Value (Get-Date)
        Set-ItemProperty -Path $regPath -Name "DriverPath" -Value $DriverPath
        Set-ItemProperty -Path $regPath -Name "SimulationMode" -Value "Active"
        
        Write-BYOVDLog "Registry persistence entries created" -Level "SUCCESS"
    }
    catch {
        Write-BYOVDLog "Registry modification failed: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Simulate file system activities
    Write-BYOVDLog "Creating post-exploitation artifacts..."
    $artifactPath = "$env:TEMP\byovd_post_exploit.txt"
    $artifactContent = @"
BYOVD Post-Exploitation Artifacts
=================================
Timestamp: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Driver: $DriverPath

Simulated Activities:
- Security process enumeration
- Registry persistence creation
- Kernel callback removal
- ETW disruption
- LSASS memory access preparation

Techniques Demonstrated:
- T1562.001: Impair Defenses
- T1547.006: Kernel Modules and Extensions
- T1003.001: OS Credential Dumping
- T1070.004: File Deletion

"@
    
    Set-Content -Path $artifactPath -Value $artifactContent
    Write-BYOVDLog "Artifacts created: $artifactPath"
}

function Remove-BYOVDArtifacts {
    Write-BYOVDLog "Cleaning up BYOVD simulation artifacts"
    
    # Remove temporary files
    if (Test-Path $script:TempDir) {
        Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-BYOVDLog "Removed temporary directory: $script:TempDir"
    }
    
    # Remove registry entries
    try {
        $regPath = "HKCU:\Software\BYOVDTest"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
            Write-BYOVDLog "Removed registry entries: $regPath"
        }
    }
    catch {
        Write-BYOVDLog "Registry cleanup failed: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Remove artifact files
    $artifactFiles = @(
        "$env:TEMP\byovd_post_exploit.txt",
        "$env:TEMP\byovd_artifacts.txt",
        "$env:TEMP\uac_test.txt"
    )
    
    foreach ($file in $artifactFiles) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            Write-BYOVDLog "Removed artifact: $file"
        }
    }
    
    Write-BYOVDLog "Cleanup completed" -Level "SUCCESS"
}

function Show-BYOVDSummary {
    Write-Host "`n=== BYOVD Simulation Summary ===" -ForegroundColor Cyan
    Write-Host "Simulation completed successfully" -ForegroundColor Green
    Write-Host "Log file: $script:LogFile" -ForegroundColor Yellow
    Write-Host "Techniques simulated:" -ForegroundColor White
    Write-Host "  - T1068: Exploitation for Privilege Escalation" -ForegroundColor Gray
    Write-Host "  - T1562.001: Impair Defenses" -ForegroundColor Gray
    Write-Host "  - T1547.006: Kernel Modules and Extensions" -ForegroundColor Gray
    Write-Host "  - T1003.001: OS Credential Dumping" -ForegroundColor Gray
    Write-Host "  - T1553.005: Driver Signature Enforcement Bypass" -ForegroundColor Gray
    Write-Host "Detection opportunities:" -ForegroundColor White
    Write-Host "  - Driver installation events" -ForegroundColor Gray
    Write-Host "  - Service creation/modification" -ForegroundColor Gray
    Write-Host "  - Registry modifications" -ForegroundColor Gray
    Write-Host "  - File system artifacts" -ForegroundColor Gray
    Write-Host "================================`n" -ForegroundColor Cyan
}

# Main execution logic
Write-BYOVDLog "BYOVD PowerShell Helper started - Action: $Action"

switch ($Action) {
    "PrepareEnvironment" {
        Write-BYOVDLog "Preparing BYOVD simulation environment"
        if (New-MockVulnerableDriver -Path $DriverPath) {
            Write-BYOVDLog "Environment preparation completed" -Level "SUCCESS"
        }
    }
    
    "InstallDriver" {
        if (Invoke-DriverInstallationSimulation -DriverPath $DriverPath) {
            Invoke-PostExploitationSimulation
        }
    }
    
    "FullSimulation" {
        New-MockVulnerableDriver -Path $DriverPath
        if (Invoke-DriverInstallationSimulation -DriverPath $DriverPath) {
            Invoke-PostExploitationSimulation
            Show-BYOVDSummary
        }
    }
    
    "Cleanup" {
        Remove-BYOVDArtifacts
    }
    
    default {
        Write-BYOVDLog "Unknown action: $Action" -Level "ERROR"
        Write-Host "Available actions: PrepareEnvironment, InstallDriver, FullSimulation, Cleanup"
    }
}

if ($CleanupOnly) {
    Remove-BYOVDArtifacts
}

Write-BYOVDLog "PowerShell helper execution completed"