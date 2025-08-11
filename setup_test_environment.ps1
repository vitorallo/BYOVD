# BYOVD Test Environment Setup Script
# Prepares a Windows system for BYOVD simulation testing
# Author: Crimson7 Threat Intelligence Team

param(
    [switch]$InstallTools = $true,
    [switch]$ConfigureLogging = $true,
    [switch]$SetupMonitoring = $true,
    [switch]$CreateTestAccounts = $false,
    [switch]$ValidateSetup = $true,
    [string]$LogPath = "$env:TEMP\byovd_setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

function Write-SetupLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "HEADER" { "Cyan" }
            default { "White" }
        }
    )
    
    Add-Content -Path $LogPath -Value $logEntry
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Banner {
    Clear-Host
    Write-Host @"
+==================================================================+
|                BYOVD Test Environment Setup                      |
|              Crimson7 Threat Intelligence Team                   |
+==================================================================+
| Prepares Windows systems for BYOVD simulation and testing       |
| WARNING: Only run on authorized test systems!                   |
+==================================================================+
"@ -ForegroundColor Cyan
}

function Install-RequiredTools {
    Write-SetupLog "Installing required tools and dependencies..." -Level "HEADER"
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-SetupLog "PowerShell Version: $psVersion"
    
    if ($psVersion.Major -lt 5) {
        Write-SetupLog "WARNING: PowerShell 5.0 or higher recommended" -Level "WARNING"
    }
    
    # Install PowerShell modules if needed
    $requiredModules = @("PSWindowsUpdate", "ImportExcel")
    
    foreach ($module in $requiredModules) {
        Write-SetupLog "Checking for module: $module"
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-SetupLog "Installing module: $module"
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-SetupLog "Module installed: $module" -Level "SUCCESS"
            } catch {
                Write-SetupLog "Failed to install module: $module - $($_.Exception.Message)" -Level "WARNING"
            }
        } else {
            Write-SetupLog "Module already available: $module" -Level "SUCCESS"
        }
    }
    
    # Check for Sysmon
    Write-SetupLog "Checking for Sysmon installation..."
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Write-SetupLog "Sysmon detected: $($sysmonService.Name)" -Level "SUCCESS"
    } else {
        Write-SetupLog "Sysmon not detected - consider installing for enhanced monitoring" -Level "WARNING"
        Write-SetupLog "Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
    }
    
    # Verify curl availability
    try {
        $curlVersion = & curl --version 2>$null
        if ($curlVersion) {
            Write-SetupLog "curl available: $($curlVersion[0])" -Level "SUCCESS"
        }
    } catch {
        Write-SetupLog "curl not available - will use PowerShell alternatives" -Level "WARNING"
    }
    
    Write-SetupLog "Tool installation check completed" -Level "SUCCESS"
}

function Configure-EventLogging {
    Write-SetupLog "Configuring enhanced event logging..." -Level "HEADER"
    
    if (-not (Test-AdminPrivileges)) {
        Write-SetupLog "Administrative privileges required for logging configuration" -Level "WARNING"
        return
    }
    
    # Enable PowerShell logging
    Write-SetupLog "Configuring PowerShell logging..."
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    
    try {
        if (-not (Test-Path $psLoggingPath)) {
            New-Item -Path $psLoggingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1
        Write-SetupLog "PowerShell script block logging enabled" -Level "SUCCESS"
    } catch {
        Write-SetupLog "Failed to configure PowerShell logging: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Enable process creation auditing
    Write-SetupLog "Configuring process creation auditing..."
    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Write-SetupLog "Process creation auditing enabled" -Level "SUCCESS"
    } catch {
        Write-SetupLog "Failed to configure process auditing: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Configure Windows Defender logging
    Write-SetupLog "Configuring Windows Defender logging..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -Force
        Write-SetupLog "Windows Defender real-time monitoring confirmed active" -Level "SUCCESS"
    } catch {
        Write-SetupLog "Windows Defender configuration warning: $($_.Exception.Message)" -Level "WARNING"
    }
    
    Write-SetupLog "Event logging configuration completed" -Level "SUCCESS"
}

function Setup-FileSystemMonitoring {
    Write-SetupLog "Setting up file system monitoring..." -Level "HEADER"
    
    # Create monitoring directories
    $monitorDirs = @(
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:SYSTEMROOT\System32\drivers"
    )
    
    foreach ($dir in $monitorDirs) {
        if (Test-Path $dir) {
            Write-SetupLog "Monitoring directory confirmed: $dir" -Level "SUCCESS"
        } else {
            Write-SetupLog "Monitoring directory not found: $dir" -Level "WARNING"
        }
    }
    
    # Create test artifact directories
    $testDirs = @(
        "$env:TEMP\byovd_test",
        "$env:TEMP\driver_test",
        "$env:TEMP\simulation_artifacts"
    )
    
    foreach ($testDir in $testDirs) {
        if (-not (Test-Path $testDir)) {
            New-Item -Path $testDir -ItemType Directory -Force | Out-Null
            Write-SetupLog "Created test directory: $testDir" -Level "SUCCESS"
        }
    }
    
    Write-SetupLog "File system monitoring setup completed" -Level "SUCCESS"
}

function Configure-TestRegistry {
    Write-SetupLog "Setting up test registry structure..." -Level "HEADER"
    
    # Create test registry keys for monitoring
    $testRegPaths = @(
        "HKCU:\Software\BYOVDTestSetup",
        "HKCU:\Software\TestEnvironment"
    )
    
    foreach ($regPath in $testRegPaths) {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-SetupLog "Created test registry path: $regPath" -Level "SUCCESS"
        }
        
        # Add setup timestamp
        Set-ItemProperty -Path $regPath -Name "SetupDate" -Value (Get-Date)
        Set-ItemProperty -Path $regPath -Name "SetupVersion" -Value "1.0"
        Set-ItemProperty -Path $regPath -Name "Purpose" -Value "BYOVD Testing Environment"
    }
    
    Write-SetupLog "Test registry structure created" -Level "SUCCESS"
}

function Install-EventSources {
    Write-SetupLog "Installing custom event sources..." -Level "HEADER"
    
    if (-not (Test-AdminPrivileges)) {
        Write-SetupLog "Administrative privileges required for event source installation" -Level "WARNING"
        return
    }
    
    $eventSources = @("BYOVD-Test", "BYOVD-Simulation", "Driver-Test")
    
    foreach ($source in $eventSources) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
                New-EventLog -LogName Application -Source $source
                Write-SetupLog "Event source created: $source" -Level "SUCCESS"
            } else {
                Write-SetupLog "Event source already exists: $source" -Level "SUCCESS"
            }
        } catch {
            Write-SetupLog "Failed to create event source: $source - $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    # Test event source
    try {
        Write-EventLog -LogName Application -Source "BYOVD-Test" -EventId 9001 -EntryType Information -Message "BYOVD test environment setup completed successfully"
        Write-SetupLog "Test event logged successfully" -Level "SUCCESS"
    } catch {
        Write-SetupLog "Failed to write test event: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Validate-TestEnvironment {
    Write-SetupLog "Validating test environment setup..." -Level "HEADER"
    
    $validationResults = @()
    
    # Check PowerShell execution policy
    $execPolicy = Get-ExecutionPolicy
    $validationResults += @{
        Test = "PowerShell Execution Policy"
        Result = $execPolicy
        Status = if ($execPolicy -ne "Restricted") { "PASS" } else { "WARN" }
    }
    
    # Check administrative privileges
    $isAdmin = Test-AdminPrivileges
    $validationResults += @{
        Test = "Administrative Privileges"
        Result = $isAdmin
        Status = if ($isAdmin) { "PASS" } else { "WARN" }
    }
    
    # Check Windows version
    $winVersion = [Environment]::OSVersion.Version
    $validationResults += @{
        Test = "Windows Version"
        Result = "$($winVersion.Major).$($winVersion.Minor)"
        Status = if ($winVersion.Major -ge 10) { "PASS" } else { "WARN" }
    }
    
    # Check available disk space
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $validationResults += @{
        Test = "Available Disk Space"
        Result = "$freeSpaceGB GB"
        Status = if ($freeSpaceGB -gt 5) { "PASS" } else { "WARN" }
    }
    
    # Check Windows Defender status
    try {
        $defenderStatus = Get-MpComputerStatus
        $validationResults += @{
            Test = "Windows Defender Status"
            Result = if ($defenderStatus.RealTimeProtectionEnabled) { "Active" } else { "Inactive" }
            Status = if ($defenderStatus.RealTimeProtectionEnabled) { "PASS" } else { "WARN" }
        }
    } catch {
        $validationResults += @{
            Test = "Windows Defender Status"
            Result = "Unknown"
            Status = "WARN"
        }
    }
    
    # Check event log access
    try {
        $recentEvents = Get-WinEvent -LogName Application -MaxEvents 1 -ErrorAction Stop
        $validationResults += @{
            Test = "Event Log Access"
            Result = "Available"
            Status = "PASS"
        }
    } catch {
        $validationResults += @{
            Test = "Event Log Access"
            Result = "Limited"
            Status = "WARN"
        }
    }
    
    # Display validation results
    Write-SetupLog "Environment Validation Results:" -Level "HEADER"
    Write-Host ""
    Write-Host "+--------------------------------+----------------+-------+" -ForegroundColor White
    Write-Host "| Test                           | Result         | Status |" -ForegroundColor White
    Write-Host "+--------------------------------+----------------+-------+" -ForegroundColor White
    
    foreach ($result in $validationResults) {
        $statusColor = switch ($result.Status) {
            "PASS" { "Green" }
            "WARN" { "Yellow" }
            "FAIL" { "Red" }
            default { "White" }
        }
        
        $testName = $result.Test.PadRight(31)
        $resultValue = $result.Result.ToString().PadRight(15)
        $status = $result.Status.PadRight(6)
        
        Write-Host "| $testName | $resultValue | " -NoNewline -ForegroundColor White
        Write-Host "$status" -NoNewline -ForegroundColor $statusColor
        Write-Host " |" -ForegroundColor White
        
        Write-SetupLog "$($result.Test): $($result.Result) [$($result.Status)]"
    }
    
    Write-Host "+--------------------------------+----------------+-------+" -ForegroundColor White
    Write-Host ""
    
    $passCount = ($validationResults | Where-Object { $_.Status -eq "PASS" }).Count
    $totalCount = $validationResults.Count
    
    Write-SetupLog "Validation Summary: $passCount/$totalCount checks passed" -Level "SUCCESS"
    
    return $validationResults
}

function Create-SetupSummary {
    Write-SetupLog "Creating setup summary..." -Level "HEADER"
    
    $summaryPath = "$env:TEMP\byovd_environment_setup_summary.txt"
    $summaryContent = @"
BYOVD Test Environment Setup Summary
===================================
Setup Date: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Setup Log: $LogPath

Configuration Applied:
- Enhanced event logging: $(if($ConfigureLogging){'Yes'}else{'No'})
- File system monitoring: $(if($SetupMonitoring){'Yes'}else{'No'})
- Required tools check: $(if($InstallTools){'Yes'}else{'No'})
- Environment validation: $(if($ValidateSetup){'Yes'}else{'No'})

Administrative Privileges: $(Test-AdminPrivileges)
PowerShell Version: $($PSVersionTable.PSVersion)
Execution Policy: $(Get-ExecutionPolicy)

Test Directories Created:
- $env:TEMP\byovd_test
- $env:TEMP\driver_test
- $env:TEMP\simulation_artifacts

Registry Keys Created:
- HKCU\Software\BYOVDTestSetup
- HKCU\Software\TestEnvironment

Event Sources Installed:
- BYOVD-Test
- BYOVD-Simulation
- Driver-Test

NEXT STEPS:
1. Copy BYOVD simulation package to test system
2. Review security monitoring configuration
3. Ensure backup and restore capabilities
4. Document test procedures and expected outcomes
5. Coordinate with security team for monitoring

SECURITY RECOMMENDATIONS:
- Run tests only on isolated systems
- Monitor all test activities
- Maintain detailed logs of all operations
- Clean up artifacts after testing
- Document findings for security improvement

CLEANUP INSTRUCTIONS:
When testing is complete:
1. Run: cleanup_verifier.ps1 -RemoveFoundArtifacts
2. Delete test directories under %TEMP%
3. Remove registry keys: HKCU\Software\BYOVD*
4. Clear application event logs if needed
5. Reset any modified security settings

Created by: BYOVD Environment Setup Script
Author: Crimson7 Threat Intelligence Team
Version: 1.0
"@
    
    Set-Content -Path $summaryPath -Value $summaryContent
    Write-SetupLog "Setup summary created: $summaryPath" -Level "SUCCESS"
    
    return $summaryPath
}

# Main execution
Write-SetupLog "BYOVD Test Environment Setup Started" -Level "HEADER"
Write-SetupLog "Configuration: InstallTools=$InstallTools, ConfigureLogging=$ConfigureLogging, SetupMonitoring=$SetupMonitoring" -Level "INFO"

Show-Banner

try {
    if ($InstallTools) {
        Install-RequiredTools
    }
    
    if ($ConfigureLogging) {
        Configure-EventLogging
        Install-EventSources
    }
    
    if ($SetupMonitoring) {
        Setup-FileSystemMonitoring
    }
    
    Configure-TestRegistry
    
    if ($ValidateSetup) {
        $validationResults = Validate-TestEnvironment
    }
    
    $summaryPath = Create-SetupSummary
    
    Write-SetupLog "BYOVD Test Environment Setup Completed Successfully" -Level "SUCCESS"
    
    Write-Host ""
    Write-Host "Setup completed successfully!" -ForegroundColor Green
    Write-Host "Summary file: $summaryPath" -ForegroundColor Cyan
    Write-Host "Setup log: $LogPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Your system is now ready for BYOVD simulation testing." -ForegroundColor Green
    Write-Host ""
    
} catch {
    Write-SetupLog "Setup failed: $($_.Exception.Message)" -Level "ERROR"
    Write-SetupLog "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    
    Write-Host "Setup failed. Check log file: $LogPath" -ForegroundColor Red
    exit 1
}

Write-SetupLog "Setup log saved: $LogPath"