# BYOVD Detection Validator - Enhanced Path Detection
# Tool to validate security controls detect BYOVD simulation activities
# Author: Crimson7 Research Team
# Version: 2.0 - Fixed path detection for nested extraction structure

param(
    [switch]$TestDriverInstallation = $false,
    [switch]$TestProcessTermination = $false,
    [switch]$TestVBSExecution = $false,
    [switch]$TestRegistryModification = $false,
    [switch]$TestFileOperations = $false,
    [switch]$TestWindowsDefender = $false,
    [switch]$TestPowerShellLogging = $false,
    [switch]$TestAttackChainIoCs = $false,
    [switch]$TestFailedTechniques = $false,
    [switch]$TestAllDetections = $false,
    [switch]$GenerateReport = $true,
    [string]$OutputPath = "$env:TEMP\byovd_detection_report.html",
    [int]$TestDurationMinutes = 5
)

# Global variables
$script:TestResults = @()
$script:StartTime = Get-Date
$script:ValidationLog = "$env:TEMP\byovd_validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-ValidationLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "DETECTION" { "Cyan" }
            default { "White" }
        }
    )
    
    Add-Content -Path $script:ValidationLog -Value $logEntry
}

function Test-SecurityEventLogging {
    param([string]$TestName, [int]$ExpectedEventID, [string]$LogName = "Application", [string]$MitreTechnique = "", [string]$MitreTactic = "")
    
    Write-ValidationLog "Testing event logging for: $TestName" -Level "INFO"
    if ($MitreTechnique) {
        Write-ValidationLog "MITRE ATT&CK: $MitreTechnique ($MitreTactic)" -Level "INFO"
    }
    
    # Skip event log testing if event ID is 0 or invalid
    if ($ExpectedEventID -eq 0) {
        Write-ValidationLog "Skipping event log check - no valid event ID provided" -Level "INFO"
        $detected = $false
    } else {
        try {
            $startTime = (Get-Date).AddMinutes(-2)
            $events = Get-WinEvent -FilterHashtable @{
                LogName = $LogName
                StartTime = $startTime
                ID = $ExpectedEventID
            } -ErrorAction SilentlyContinue
            
            $detected = $events.Count -gt 0
        } catch {
            Write-ValidationLog "Event log query failed: $($_.Exception.Message)" -Level "WARNING"
            $detected = $false
        }
    }
    
    $result = @{
        TestName = $TestName
        DetectionMethod = "Event Logging"
        EventID = $ExpectedEventID
        LogName = $LogName
        Detected = $detected
        EventCount = if ($events) { $events.Count } else { 0 }
        Details = if ($detected) { "Events found: $(if ($events) { $events.Count } else { 0 })" } else { "No events detected" }
        MitreTechnique = $MitreTechnique
        MitreTactic = $MitreTactic
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($detected) {
        Write-ValidationLog "[+] DETECTION: $TestName - Found $($events.Count) events with ID $ExpectedEventID" -Level "DETECTION"
    } else {
        Write-ValidationLog "[-] NO DETECTION: $TestName - No events found with ID $ExpectedEventID" -Level "WARNING"
    }
    
    return $detected
}

function Test-ProcessCreationDetection {
    param([string]$ProcessName, [string]$CommandLine = "")
    
    Write-ValidationLog "Testing process creation detection for: $ProcessName" -Level "INFO"
    
    # Check Sysmon Event ID 1 (Process Creation)
    $sysmonDetected = Test-SecurityEventLogging -TestName "Process Creation - $ProcessName" -EventID 1 -LogName "Microsoft-Windows-Sysmon/Operational"
    
    # Check Windows Security Event ID 4688 (Process Creation)
    $securityDetected = Test-SecurityEventLogging -TestName "Security Process Creation - $ProcessName" -EventID 4688 -LogName "Security"
    
    # Check running processes
    $runningProcess = Get-Process -Name $ProcessName.Replace('.exe', '') -ErrorAction SilentlyContinue
    $processDetected = $runningProcess -ne $null
    
    if ($processDetected) {
        Write-ValidationLog "[+] DETECTION: Process $ProcessName is currently running" -Level "DETECTION"
    }
    
    return ($sysmonDetected -or $securityDetected -or $processDetected)
}

function Test-FileSystemDetection {
    param([string]$FilePath, [string]$Operation = "Created", [string]$MitreTechnique = "", [string]$MitreTactic = "")
    
    Write-ValidationLog "Testing file system detection for: $FilePath" -Level "INFO"
    if ($MitreTechnique) {
        Write-ValidationLog "MITRE ATT&CK: $MitreTechnique ($MitreTactic)" -Level "INFO"
    }
    
    # Check Sysmon Event ID 11 (File Created)
    $sysmonDetected = $false
    if ($Operation -eq "Created") {
        $sysmonDetected = Test-SecurityEventLogging -TestName "File Creation - $FilePath" -EventID 11 -LogName "Microsoft-Windows-Sysmon/Operational" -MitreTechnique $MitreTechnique -MitreTactic $MitreTactic
    }
    
    # Check file exists
    $fileExists = Test-Path $FilePath
    
    if ($fileExists) {
        $fileInfo = Get-Item $FilePath
        $fileSize = $fileInfo.Length
        Write-ValidationLog "[+] DETECTION: File exists - $FilePath ($fileSize bytes)" -Level "DETECTION"
    } else {
        Write-ValidationLog "[-] File not found: $FilePath" -Level "WARNING"
    }
    
    return ($sysmonDetected -or $fileExists)
}

function Test-RegistryDetection {
    param([string]$RegistryPath, [string]$ValueName = "")
    
    Write-ValidationLog "Testing registry detection for: $RegistryPath" -Level "INFO"
    
    # Check Sysmon Event ID 13 (Registry Value Set)
    $sysmonDetected = Test-SecurityEventLogging -TestName "Registry Modification - $RegistryPath" -EventID 13 -LogName "Microsoft-Windows-Sysmon/Operational"
    
    # Check registry key/value exists
    $regExists = Test-Path $RegistryPath
    
    if ($regExists -and $ValueName) {
        try {
            $value = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
            if ($value) {
                Write-ValidationLog "[+] DETECTION: Registry value exists - $RegistryPath\$ValueName" -Level "DETECTION"
                return $true
            }
        } catch {}
    } elseif ($regExists) {
        Write-ValidationLog "[+] DETECTION: Registry key exists - $RegistryPath" -Level "DETECTION"
        return $true
    }
    
    Write-ValidationLog "[-] Registry path not found: $RegistryPath" -Level "WARNING"
    return $sysmonDetected
}

function Test-ServiceDetection {
    param([string]$ServiceName)
    
    Write-ValidationLog "Testing service detection for: $ServiceName" -Level "INFO"
    
    # Check Windows Event ID 7045 (Service Installation)
    $serviceInstallDetected = Test-SecurityEventLogging -TestName "Service Installation - $ServiceName" -EventID 7045 -LogName "System"
    
    # Check if service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $serviceExists = $service -ne $null
    
    if ($serviceExists) {
        Write-ValidationLog "[+] DETECTION: Service exists - $ServiceName (Status: $($service.Status))" -Level "DETECTION"
    }
    
    return ($serviceInstallDetected -or $serviceExists)
}

function Invoke-DriverInstallationTest {
    Write-ValidationLog "=== Starting Driver Installation Detection Test ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Tested:" -Level "INFO"
    Write-ValidationLog "  - T1068: Exploitation for Privilege Escalation (CVE-2015-2291)" -Level "INFO"
    Write-ValidationLog "  - T1014: Rootkit (Kernel-level persistence)" -Level "INFO"
    Write-ValidationLog "  - T1543.003: Windows Service (Driver service creation)" -Level "INFO"
    Write-ValidationLog "  - T1547.006: Kernel Modules and Extensions" -Level "INFO"
    Write-ValidationLog "  - T1070.004: File Deletion (Indicator Removal)" -Level "INFO"
    
    # Look for actual BYOVD simulation artifacts first (fixed path separators)
    $actualDriverPaths = @(
        "$env:TEMP\nvidiadrivers\nvidiadrivers\iqvw64.sys",  # Nested structure from extraction
        "$env:TEMP\nvidiadrivers\iqvw64.sys",
        "$env:TEMP\iqvw64.sys",
        ".\nvidiadrivers\nvidiadrivers\iqvw64.sys",  # Local nested structure
        ".\nvidiadrivers\iqvw64.sys",
        ".\iqvw64.sys"
    )
    
    $testDriverPath = $null
    foreach ($path in $actualDriverPaths) {
        if (Test-Path $path) {
            $testDriverPath = $path
            Write-ValidationLog "Found actual BYOVD driver artifact: $path" -Level "SUCCESS"
            break
        }
    }
    
    # If no actual artifact found, create test driver for validation purposes
    if (-not $testDriverPath) {
        $testDriverPath = "$env:TEMP\iqvw64.sys"
        Write-ValidationLog "No existing BYOVD driver found, creating test artifact" -Level "INFO"
        # Create realistic mock driver content matching the actual driver_loader.vbs
        $driverContent = "MOCK VULNERABLE DRIVER - BYOVD DETECTION TEST`r`n" + 
                        "Driver: iqvw64.sys (Intel Ethernet Diagnostics)`r`n" +
                        "CVE: CVE-2015-2291 (Write-What-Where)`r`n" +
                        "Created: $(Get-Date)`r`n" +
                        "Purpose: Detection validation test"
        Set-Content -Path $testDriverPath -Value $driverContent
    }
    
    $testServiceName = "iqvw64"  # Use actual service name from simulation
    
    # Test file creation detection
    Test-FileSystemDetection -FilePath $testDriverPath -Operation "Created" -MitreTechnique "T1068" -MitreTactic "Privilege Escalation"
    
    # Simulate service creation (admin required)
    if (Test-AdminPrivileges) {
        try {
            $result = Start-Process -FilePath "sc.exe" -ArgumentList "create", $testServiceName, "binPath=", "`"$testDriverPath`"", "type=", "kernel" -Wait -PassThru -NoNewWindow
            if ($result.ExitCode -eq 0) {
                # Test service detection
                Test-ServiceDetection -ServiceName $testServiceName
                
                # Cleanup
                Start-Process -FilePath "sc.exe" -ArgumentList "delete", $testServiceName -Wait -NoNewWindow | Out-Null
            }
        } catch {
            Write-ValidationLog "Service creation failed: $($_.Exception.Message)" -Level "WARNING"
        }
    } else {
        Write-ValidationLog "Skipping service tests - administrative privileges required" -Level "WARNING"
    }
    
    # Cleanup
    Remove-Item $testDriverPath -Force -ErrorAction SilentlyContinue
}

function Invoke-ProcessTerminationTest {
    Write-ValidationLog "=== Starting Process Termination Detection Test ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Tested:" -Level "INFO"
    Write-ValidationLog "  - T1562.001: Impair Defenses (Security software termination)" -Level "INFO"
    Write-ValidationLog "  - T1003: OS Credential Dumping (LSASS access prep)" -Level "INFO"
    Write-ValidationLog "  - T1055: Process Injection (Process hollowing)" -Level "INFO"
    Write-ValidationLog "  - T1059: Command and Scripting Interpreter (Process Creation)" -Level "INFO"
    
    # Start test processes
    $testProcesses = @("notepad.exe", "calc.exe")
    $startedProcesses = @()
    
    foreach ($proc in $testProcesses) {
        try {
            $process = Start-Process $proc -PassThru
            $startedProcesses += $process
            Write-ValidationLog "Started test process: $proc (PID: $($process.Id))" -Level "INFO"
        } catch {
            Write-ValidationLog "Failed to start process: $proc" -Level "WARNING"
        }
    }
    
    Start-Sleep -Seconds 2
    
    # Test process creation detection
    foreach ($proc in $testProcesses) {
        Test-ProcessCreationDetection -ProcessName $proc
    }
    
    # Simulate process termination
    foreach ($process in $startedProcesses) {
        if ($process -and $process.Id) {
            try {
                # Check if process is still running before attempting to terminate
                $runningProcess = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
                if ($runningProcess) {
                    Stop-Process -Id $process.Id -Force
                    Write-ValidationLog "Terminated test process: $($process.ProcessName) (PID: $($process.Id))" -Level "INFO"
                } else {
                    Write-ValidationLog "Process already terminated: $($process.ProcessName) (PID: $($process.Id))" -Level "INFO"
                }
                
                # Test process termination detection (Event ID 5 is Sysmon process terminate)
                Test-SecurityEventLogging -TestName "Process Termination - $($process.ProcessName)" -EventID 5 -LogName "Microsoft-Windows-Sysmon/Operational" -MitreTechnique "T1562.001" -MitreTactic "Defense Evasion"
            } catch {
                Write-ValidationLog "Failed to terminate process: $($process.ProcessName) - $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
}

function Invoke-VBSExecutionTest {
    Write-ValidationLog "=== Starting VBS Execution Detection Test ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Tested:" -Level "INFO"
    Write-ValidationLog "  - T1059.005: Visual Basic Script Execution" -Level "INFO"
    Write-ValidationLog "  - T1105: Ingress Tool Transfer (Script Delivery)" -Level "INFO"
    
    # Look for actual BYOVD VBS files first (fixed path separators)
    $actualVBSPaths = @(
        "$env:TEMP\nvidiadrivers\nvidiadrivers\driver_loader.vbs",  # Nested structure from extraction
        "$env:TEMP\nvidiadrivers\nvidiadrivers\install.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\update.vbs",
        "$env:TEMP\nvidiadrivers\driver_loader.vbs",
        "$env:TEMP\nvidiadrivers\install.vbs", 
        "$env:TEMP\nvidiadrivers\update.vbs",
        ".\nvidiadrivers\nvidiadrivers\driver_loader.vbs",  # Local nested structure
        ".\nvidiadrivers\nvidiadrivers\install.vbs",
        ".\nvidiadrivers\nvidiadrivers\update.vbs",
        ".\nvidiadrivers\driver_loader.vbs",
        ".\nvidiadrivers\install.vbs",
        ".\nvidiadrivers\update.vbs"
    )
    
    $testVBSPath = $null
    foreach ($path in $actualVBSPaths) {
        if (Test-Path $path) {
            $testVBSPath = $path
            Write-ValidationLog "Found actual BYOVD VBS artifact: $path" -Level "SUCCESS"
            break
        }
    }
    
    # If no actual VBS found, create test VBS for validation purposes
    if (-not $testVBSPath) {
        $testVBSPath = "$env:TEMP\byovd_detection_test.vbs"
        Write-ValidationLog "No existing BYOVD VBS found, creating test artifact" -Level "INFO"
        
        # Create test VBS script
        $vbsContent = @'
' BYOVD Detection Test VBS - Simulating driver_loader.vbs behavior
CreateObject("WScript.Shell").Run "cmd.exe /c echo BYOVD VBS Detection Test > " & CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") & "\vbs_test_output.txt", 0, True
'@
        Set-Content -Path $testVBSPath -Value $vbsContent
    }
    
    # Test VBS file creation
    Test-FileSystemDetection -FilePath $testVBSPath -Operation "Created" -MitreTechnique "T1105" -MitreTactic "Command and Control"
    
    # Execute VBS script with timeout
    try {
        $vbsProcess = Start-Process "wscript.exe" -ArgumentList "`"$testVBSPath`"" -PassThru -WindowStyle Hidden
        Write-ValidationLog "VBS script started (PID: $($vbsProcess.Id))" -Level "INFO"
        
        # Wait with timeout (10 seconds max)
        $timeout = 10000 # milliseconds
        if ($vbsProcess.WaitForExit($timeout)) {
            Write-ValidationLog "VBS script completed successfully" -Level "SUCCESS"
        } else {
            Write-ValidationLog "VBS script timed out, terminating..." -Level "WARNING"
            $vbsProcess.Kill()
        }
        
        # Test VBS execution detection
        Test-ProcessCreationDetection -ProcessName "wscript.exe" -CommandLine $testVBSPath
        
        # Check for output file
        $outputFile = "$env:TEMP\vbs_test_output.txt"
        if (Test-Path $outputFile) {
            Test-FileSystemDetection -FilePath $outputFile -Operation "Created"
            Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
        }
        
    } catch {
        Write-ValidationLog "VBS execution failed: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Cleanup
    Remove-Item $testVBSPath -Force -ErrorAction SilentlyContinue
}

function Invoke-RegistryModificationTest {
    Write-ValidationLog "=== Starting Registry Modification Detection Test ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Tested:" -Level "INFO"
    Write-ValidationLog "  - T1112: Modify Registry (Persistence & Configuration)" -Level "INFO"
    Write-ValidationLog "  - T1547.001: Boot or Logon Autostart Execution" -Level "INFO"
    
    # Look for actual BYOVD registry keys first
    $actualRegPaths = @(
        "HKCU:\Software\Intel\Diagnostics",
        "HKCU:\Software\DriverTest\iqvw64",
        "HKCU:\Software\BYOVDNVIDIATest"
    )
    
    $testRegPath = $null
    $foundExistingKey = $false
    
    foreach ($regPath in $actualRegPaths) {
        if (Test-Path $regPath) {
            $testRegPath = $regPath
            $foundExistingKey = $true
            Write-ValidationLog "Found actual BYOVD registry artifact: $regPath" -Level "SUCCESS"
            break
        }
    }
    
    # If no actual registry key found, create test key for validation purposes
    if (-not $testRegPath) {
        $testRegPath = "HKCU:\Software\Intel\Diagnostics"
        Write-ValidationLog "No existing BYOVD registry keys found, creating test artifact" -Level "INFO"
    }
    
    # Create or update test registry key
    try {
        if (-not $foundExistingKey) {
            New-Item -Path $testRegPath -Force | Out-Null
            Write-ValidationLog "Created test registry key: $testRegPath" -Level "INFO"
        }
        
        # Test registry key detection
        Test-RegistryDetection -RegistryPath $testRegPath
        
        # Add test values that match actual BYOVD simulation
        if (-not $foundExistingKey) {
            $testValues = @{
                "InstallDate" = (Get-Date).ToString()
                "Version" = "7.1.0.1041"
                "ServiceName" = "iqvw64"
                "DriverPath" = "$env:SYSTEMROOT\System32\drivers\iqvw64.sys"
            }
        } else {
            # If we found existing keys, just add a detection test marker
            $testValues = @{
                "DetectionTest" = "Validated - $(Get-Date)"
            }
        }
        
        foreach ($value in $testValues.GetEnumerator()) {
            Set-ItemProperty -Path $testRegPath -Name $value.Key -Value $value.Value
            Write-ValidationLog "Set registry value: $($value.Key) = $($value.Value)" -Level "INFO"
            
            # Test registry value detection
            Test-RegistryDetection -RegistryPath $testRegPath -ValueName $value.Key
        }
        
    } catch {
        Write-ValidationLog "Registry operation failed: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Cleanup
    try {
        Remove-Item -Path $testRegPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-ValidationLog "Cleaned up test registry key" -Level "INFO"
    } catch {}
}

function Invoke-FileOperationsTest {
    Write-ValidationLog "=== Starting File Operations Detection Test ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Tested:" -Level "INFO"
    Write-ValidationLog "  - T1070.004: File Deletion (Indicator Removal)" -Level "INFO"
    Write-ValidationLog "  - T1105: Ingress Tool Transfer (File Operations)" -Level "INFO"
    Write-ValidationLog "  - T1036: Masquerading (File Naming)" -Level "INFO"
    
    $testDir = "$env:TEMP\byovd_file_test"
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    
    # Test various file operations with realistic BYOVD filenames
    $testFiles = @(
        @{Name="iqvw64.sys"; Content="Mock vulnerable Intel Ethernet driver for detection testing - CVE-2015-2291"},
        @{Name="iqvw64_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"; Content="BYOVD driver installation log"},
        @{Name="config.ini"; Content="BYOVD configuration file test"},
        @{Name="nvidia_backup.reg"; Content="NVIDIA driver registry backup simulation"},
        @{Name="byovd_artifacts.txt"; Content="BYOVD attack artifacts file"},
        @{Name="iqvw64_errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"; Content="BYOVD error logging test"},
        @{Name="iqvw64_execution_summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"; Content="BYOVD execution summary test"}
    )
    
    foreach ($file in $testFiles) {
        $filePath = Join-Path $testDir $file.Name
        
        # Create file
        Set-Content -Path $filePath -Value "$($file.Content)`nCreated: $(Get-Date)"
        Test-FileSystemDetection -FilePath $filePath -Operation "Created" -MitreTechnique "T1105" -MitreTactic "Command and Control"
        
        # Modify file
        Add-Content -Path $filePath -Value "`nModified: $(Get-Date)"
        
        # Test file existence before deletion
        if (Test-Path $filePath) {
            # Delete file
            Remove-Item $filePath -Force
            Test-SecurityEventLogging -TestName "File Deletion - $($file.Name)" -EventID 23 -LogName "Microsoft-Windows-Sysmon/Operational" -MitreTechnique "T1070.004" -MitreTactic "Defense Evasion"
        } else {
            Write-ValidationLog "File not found for deletion test: $filePath" -Level "WARNING"
        }
    }
    
    # Cleanup
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-AdminPrivileges {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-WindowsDefenderDetection {
    param([string]$TestName, [string]$MitreTechnique = "", [string]$MitreTactic = "")
    
    Write-ValidationLog "Testing Windows Defender detection for: $TestName" -Level "INFO"
    if ($MitreTechnique) {
        Write-ValidationLog "MITRE ATT&CK: $MitreTechnique ($MitreTactic)" -Level "INFO"
    }
    
    $detectionResults = @{
        EventLogDetection = $false
        StatusChange = $false
        ThreatHistory = $false
        Details = @()
    }
    
    # Test Windows Defender Event Logs
    try {
        $defenderEvents = @(
            @{ ID = 1116; Description = "Malware detection" },
            @{ ID = 1117; Description = "Action taken on malware" },
            @{ ID = 5001; Description = "Real-time protection disabled" },
            @{ ID = 5007; Description = "Configuration changed" }
        )
        
        $startTime = (Get-Date).AddMinutes(-5)
        foreach ($event in $defenderEvents) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = "Microsoft-Windows-Windows Defender/Operational"
                    StartTime = $startTime
                    ID = $event.ID
                } -ErrorAction SilentlyContinue
                
                if ($events -and $events.Count -gt 0) {
                    $detectionResults.EventLogDetection = $true
                    $detectionResults.Details += "Found $($events.Count) Defender events (ID: $($event.ID) - $($event.Description))"
                    Write-ValidationLog "[+] Windows Defender event detected: ID $($event.ID) - $($event.Description)" -Level "DETECTION"
                }
            } catch {
                Write-ValidationLog "Could not check Defender event ID $($event.ID): $($_.Exception.Message)" -Level "WARNING"
            }
        }
    } catch {
        Write-ValidationLog "Windows Defender event log not accessible: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check Windows Defender Status
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $statusInfo = @()
            $statusInfo += "Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
            $statusInfo += "Cloud Protection: $($defenderStatus.MapsMembershipEnabled)"
            $statusInfo += "Tamper Protection: $($defenderStatus.TamperProtectionSource)"
            $statusInfo += "Last Quick Scan: $($defenderStatus.QuickScanEndTime)"
            
            $detectionResults.Details += $statusInfo
            $detectionResults.StatusChange = $true
            
            Write-ValidationLog "[+] Windows Defender status retrieved successfully" -Level "DETECTION"
        }
    } catch {
        Write-ValidationLog "Could not retrieve Windows Defender status: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check recent threat history
    try {
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-24) }
        if ($threats -and $threats.Count -gt 0) {
            $detectionResults.ThreatHistory = $true
            $detectionResults.Details += "Recent threats detected: $($threats.Count) in last 24 hours"
            Write-ValidationLog "[+] Windows Defender recent threat activity: $($threats.Count) detections" -Level "DETECTION"
        }
    } catch {
        Write-ValidationLog "Could not retrieve Windows Defender threat history: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check exclusions that might affect detection
    try {
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
        if ($exclusions) {
            $tempExcluded = $exclusions.ExclusionPath | Where-Object { $_ -like "*temp*" -or $_ -like "*tmp*" }
            if ($tempExcluded) {
                $detectionResults.Details += "WARNING: TEMP directories excluded from scanning: $($tempExcluded -join '; ')"
                Write-ValidationLog "[-] Windows Defender exclusions may impact detection: $($tempExcluded -join '; ')" -Level "WARNING"
            }
        }
    } catch {
        Write-ValidationLog "Could not check Windows Defender exclusions: $($_.Exception.Message)" -Level "WARNING"
    }
    
    $detected = $detectionResults.EventLogDetection -or $detectionResults.StatusChange -or $detectionResults.ThreatHistory
    
    $result = @{
        TestName = $TestName
        DetectionMethod = "Windows Defender"
        MitreTechnique = $MitreTechnique
        MitreTactic = $MitreTactic
        Detected = $detected
        Details = $detectionResults.Details -join "; "
        EventCount = 0
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($detected) {
        Write-ValidationLog "[+] DETECTION: Windows Defender - $TestName" -Level "DETECTION"
    } else {
        Write-ValidationLog "[-] NO DETECTION: Windows Defender - $TestName" -Level "WARNING"
    }
    
    return $detected
}

function Test-PowerShellLoggingDetection {
    param([string]$TestName, [string]$CommandPattern = "", [string]$MitreTechnique = "", [string]$MitreTactic = "")
    
    Write-ValidationLog "Testing PowerShell logging detection for: $TestName" -Level "INFO"
    if ($MitreTechnique) {
        Write-ValidationLog "MITRE ATT&CK: $MitreTechnique ($MitreTactic)" -Level "INFO"
    }
    
    $detectionResults = @{
        ModuleLogging = $false
        ScriptBlockLogging = $false
        TranscriptionLogging = $false
        Details = @()
    }
    
    $startTime = (Get-Date).AddMinutes(-10)
    
    # Test PowerShell Module Logging (Event ID 4103)
    try {
        $moduleEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-PowerShell/Operational"
            StartTime = $startTime
            ID = 4103
        } -ErrorAction SilentlyContinue
        
        if ($moduleEvents) {
            $relevantEvents = $moduleEvents | Where-Object { 
                if ($CommandPattern) {
                    $_.Message -like "*$CommandPattern*"
                } else {
                    $_.Message -like "*Expand-Archive*" -or 
                    $_.Message -like "*wscript*" -or 
                    $_.Message -like "*BYOVD*"
                }
            }
            
            if ($relevantEvents -and $relevantEvents.Count -gt 0) {
                $detectionResults.ModuleLogging = $true
                $detectionResults.Details += "PowerShell module logging events: $($relevantEvents.Count)"
                Write-ValidationLog "[+] PowerShell module logging detected: $($relevantEvents.Count) events" -Level "DETECTION"
            }
        }
    } catch {
        Write-ValidationLog "Could not check PowerShell module logging: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Test PowerShell Script Block Logging (Event ID 4104)
    try {
        $scriptEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-PowerShell/Operational"
            StartTime = $startTime
            ID = 4104
        } -ErrorAction SilentlyContinue
        
        if ($scriptEvents) {
            $relevantEvents = $scriptEvents | Where-Object { 
                if ($CommandPattern) {
                    $_.Message -like "*$CommandPattern*"
                } else {
                    $_.Message -like "*Expand-Archive*" -or 
                    $_.Message -like "*Start-Process*" -or 
                    $_.Message -like "*wscript*" -or
                    $_.Message -like "*BYOVD*"
                }
            }
            
            if ($relevantEvents -and $relevantEvents.Count -gt 0) {
                $detectionResults.ScriptBlockLogging = $true
                $detectionResults.Details += "PowerShell script block logging events: $($relevantEvents.Count)"
                Write-ValidationLog "[+] PowerShell script block logging detected: $($relevantEvents.Count) events" -Level "DETECTION"
            }
        }
    } catch {
        Write-ValidationLog "Could not check PowerShell script block logging: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check if PowerShell logging is properly configured
    try {
        $psLoggingConfig = @{
            ModuleLogging = $false
            ScriptBlockLogging = $false
            Transcription = $false
        }
        
        # Check registry for PowerShell logging configuration
        $moduleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $scriptBlockLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        if (Test-Path $moduleLoggingPath) {
            $moduleEnabled = Get-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
            if ($moduleEnabled -and $moduleEnabled.EnableModuleLogging -eq 1) {
                $psLoggingConfig.ModuleLogging = $true
                $detectionResults.Details += "PowerShell module logging configured"
            }
        }
        
        if (Test-Path $scriptBlockLoggingPath) {
            $scriptEnabled = Get-ItemProperty -Path $scriptBlockLoggingPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            if ($scriptEnabled -and $scriptEnabled.EnableScriptBlockLogging -eq 1) {
                $psLoggingConfig.ScriptBlockLogging = $true
                $detectionResults.Details += "PowerShell script block logging configured"
            }
        }
        
        if (Test-Path $transcriptionPath) {
            $transEnabled = Get-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -ErrorAction SilentlyContinue
            if ($transEnabled -and $transEnabled.EnableTranscripting -eq 1) {
                $psLoggingConfig.Transcription = $true
                $detectionResults.Details += "PowerShell transcription configured"
            }
        }
        
        if (-not ($psLoggingConfig.ModuleLogging -or $psLoggingConfig.ScriptBlockLogging)) {
            $detectionResults.Details += "WARNING: PowerShell logging may not be fully configured"
            Write-ValidationLog "[-] PowerShell logging not fully configured - may miss detections" -Level "WARNING"
        }
        
    } catch {
        Write-ValidationLog "Could not check PowerShell logging configuration: $($_.Exception.Message)" -Level "WARNING"
    }
    
    $detected = $detectionResults.ModuleLogging -or $detectionResults.ScriptBlockLogging
    
    $result = @{
        TestName = $TestName
        DetectionMethod = "PowerShell Logging"
        MitreTechnique = $MitreTechnique
        MitreTactic = $MitreTactic
        Detected = $detected
        Details = $detectionResults.Details -join "; "
        EventCount = 0
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($detected) {
        Write-ValidationLog "[+] DETECTION: PowerShell Logging - $TestName" -Level "DETECTION"
    } else {
        Write-ValidationLog "[-] NO DETECTION: PowerShell Logging - $TestName" -Level "WARNING"
    }
    
    return $detected
}

function Validate-AttackChainIoCs {
    param([string]$TestName = "Attack Chain IoC Validation", [string]$MitreTechnique = "", [string]$MitreTactic = "")
    
    Write-ValidationLog "=== Starting Attack Chain IoC Validation ===" -Level "INFO"
    Write-ValidationLog "MITRE ATT&CK Techniques Validated:" -Level "INFO"
    Write-ValidationLog "  - T1105: Ingress Tool Transfer (File artifacts)" -Level "INFO"
    Write-ValidationLog "  - T1059.001: PowerShell (Archive extraction)" -Level "INFO"
    Write-ValidationLog "  - T1059.005: VBS Execution (Script artifacts)" -Level "INFO"
    Write-ValidationLog "  - T1112: Registry Modification (Persistence artifacts)" -Level "INFO"
    
    $iocResults = @{
        FileArtifacts = @()
        RegistryArtifacts = @()
        ProcessArtifacts = @()
        LogArtifacts = @()
        TotalFound = 0
    }
    
    # Check file-based IoCs from attack chain scripts
    Write-ValidationLog "Checking file-based IoCs..." -Level "INFO"
    
    $fileIoCs = @(
        "$env:TEMP\nvidiadrivers.zip",
        "$env:TEMP\nvidiadrivers",
        "$env:TEMP\nvidiadrivers\nvidiadrivers",  # Nested extraction directory
        "$env:TEMP\nvidia_*.txt",
        "$env:TEMP\byovd_*.txt",
        "$env:TEMP\*_iocs.txt",
        "$env:TEMP\*driver*.log",
        "$env:TEMP\vbs_*.log",
        "$env:TEMP\byovd_attack_simulation_*.log",
        "$env:TEMP\*.vbs",
        "$env:TEMP\iqvw64_*.log",
        "$env:TEMP\*exploit_artifacts*.txt",
        "$env:TEMP\nvidia_install_*.log",
        "$env:TEMP\nvidia_update_check.vbs",
        "$env:TEMP\iqvw64_errors_*.log",
        "$env:TEMP\iqvw64_execution_summary_*.txt",
        "$env:TEMP\*iqvw64*.sys",  # Add driver file patterns
        "$env:TEMP\nvidiadrivers\*iqvw64*.sys",  # Driver in extraction directory
        "$env:TEMP\nvidiadrivers\nvidiadrivers\*iqvw64*.sys"  # Driver in nested structure
    )
    
    foreach ($ioc in $fileIoCs) {
        try {
            if ($ioc -like "*`**" -or $ioc -like "*`?*") {
                # Pattern matching
                $files = Get-ChildItem $ioc -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $iocResults.FileArtifacts += @{
                        Path = $file.FullName
                        Size = $file.Length
                        LastModified = $file.LastWriteTime
                        Type = "File Pattern Match"
                    }
                    Write-ValidationLog "[+] IoC DETECTED: File artifact - $($file.Name)" -Level "DETECTION"
                }
            } else {
                # Direct path check
                if (Test-Path $ioc) {
                    $item = Get-Item $ioc
                    $iocResults.FileArtifacts += @{
                        Path = $item.FullName
                        Size = if ($item.PSIsContainer) { "Directory" } else { $item.Length }
                        LastModified = $item.LastWriteTime
                        Type = "Direct Match"
                    }
                    Write-ValidationLog "[+] IoC DETECTED: File artifact - $($item.Name)" -Level "DETECTION"
                }
            }
        } catch {
            Write-ValidationLog "Could not check file IoC $ioc`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Check registry-based IoCs from attack chain scripts
    Write-ValidationLog "Checking registry-based IoCs..." -Level "INFO"
    
    $registryIoCs = @(
        "HKCU:\Software\BYOVDNVIDIATest",
        "HKCU:\Software\BYOVDNVIDIASetup", 
        "HKCU:\Software\VBSBYOVDTest",
        "HKCU:\Software\BYOVDTestSetup",
        "HKCU:\Software\TestEnvironment",
        "HKCU:\Software\Intel\Diagnostics",
        "HKCU:\Software\DriverTest\iqvw64",
        "HKCU:\Software\NVIDIA Corporation\NvContainer"
    )
    
    foreach ($regPath in $registryIoCs) {
        try {
            if (Test-Path $regPath) {
                $values = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $regValues = @()
                if ($values) {
                    $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                        $regValues += "$($_.Name)=$($_.Value)"
                    }
                }
                
                $iocResults.RegistryArtifacts += @{
                    Path = $regPath
                    Values = $regValues
                    LastModified = (Get-Item $regPath).LastWriteTime
                }
                Write-ValidationLog "[+] IoC DETECTED: Registry artifact - $regPath" -Level "DETECTION"
            }
        } catch {
            Write-ValidationLog "Could not check registry IoC $regPath`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Check process-based IoCs (recent executions)
    Write-ValidationLog "Checking process-based IoCs..." -Level "INFO"
    
    $processIoCs = @(
        @{ Name = "wscript"; Args = "*temp*" },
        @{ Name = "powershell"; Args = "*Expand-Archive*" },
        @{ Name = "powershell"; Args = "*nvidiadrivers*" }
    )
    
    # Check recent PowerShell and VBS activity via event logs
    try {
        $startTime = (Get-Date).AddHours(-2)
        
        # Check for wscript executions
        $wscriptEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            StartTime = $startTime
            ID = 4688
        } -ErrorAction SilentlyContinue | Where-Object { 
            $_.Message -like "*wscript*" -and $_.Message -like "*temp*"
        }
        
        foreach ($event in $wscriptEvents) {
            $iocResults.ProcessArtifacts += @{
                Process = "wscript.exe"
                EventTime = $event.TimeCreated
                EventId = $event.Id
                Details = "VBS execution from temp directory"
            }
            Write-ValidationLog "[+] IoC DETECTED: Process execution - wscript.exe from temp" -Level "DETECTION"
        }
        
        # Check PowerShell activity
        Test-PowerShellLoggingDetection -TestName "Attack Chain PowerShell Activity" -CommandPattern "Expand-Archive" -MitreTechnique "T1059.001" -MitreTactic "Execution"
        
    } catch {
        Write-ValidationLog "Could not check process IoCs: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check log artifacts from attack simulation
    Write-ValidationLog "Checking log artifacts..." -Level "INFO"
    
    $logPatterns = @(
        "$env:TEMP\byovd_attack_simulation_*.log",
        "$env:TEMP\byovd_attack_chain_test_*.log",
        "$env:TEMP\nvidia_powershell_setup_*.log",
        "$env:TEMP\byovd_validation_*.log"
    )
    
    foreach ($pattern in $logPatterns) {
        try {
            $logs = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            foreach ($log in $logs) {
                $content = Get-Content $log -Head 10 -ErrorAction SilentlyContinue
                $iocResults.LogArtifacts += @{
                    Path = $log.FullName
                    Size = $log.Length
                    LastModified = $log.LastWriteTime
                    Preview = $content -join "; "
                }
                Write-ValidationLog "[+] IoC DETECTED: Log artifact - $($log.Name)" -Level "DETECTION"
            }
        } catch {
            Write-ValidationLog "Could not check log pattern $pattern`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Calculate totals
    $iocResults.TotalFound = $iocResults.FileArtifacts.Count + 
                             $iocResults.RegistryArtifacts.Count + 
                             $iocResults.ProcessArtifacts.Count + 
                             $iocResults.LogArtifacts.Count
    
    # Test Windows Defender detection of these IoCs
    if ($iocResults.TotalFound -gt 0) {
        Test-WindowsDefenderDetection -TestName "Attack Chain Artifacts" -MitreTechnique "T1105" -MitreTactic "Command and Control"
    }
    
    $detected = $iocResults.TotalFound -gt 0
    
    # Create detailed result
    $details = @()
    if ($iocResults.FileArtifacts.Count -gt 0) {
        $details += "Files: $($iocResults.FileArtifacts.Count)"
    }
    if ($iocResults.RegistryArtifacts.Count -gt 0) {
        $details += "Registry: $($iocResults.RegistryArtifacts.Count)"
    }
    if ($iocResults.ProcessArtifacts.Count -gt 0) {
        $details += "Processes: $($iocResults.ProcessArtifacts.Count)"
    }
    if ($iocResults.LogArtifacts.Count -gt 0) {
        $details += "Logs: $($iocResults.LogArtifacts.Count)"
    }
    
    $result = @{
        TestName = $TestName
        DetectionMethod = "IoC Validation"
        MitreTechnique = "Multiple"
        MitreTactic = "Multiple"
        Detected = $detected
        Details = "Total IoCs found: $($iocResults.TotalFound) [$($details -join ', ')]"
        EventCount = $iocResults.TotalFound
        Timestamp = Get-Date
        IoCArtifacts = $iocResults
    }
    
    $script:TestResults += $result
    
    Write-ValidationLog "=== Attack Chain IoC Validation Summary ===" -Level "INFO"
    Write-ValidationLog "File artifacts: $($iocResults.FileArtifacts.Count)" -Level "INFO"
    Write-ValidationLog "Registry artifacts: $($iocResults.RegistryArtifacts.Count)" -Level "INFO"
    Write-ValidationLog "Process artifacts: $($iocResults.ProcessArtifacts.Count)" -Level "INFO"
    Write-ValidationLog "Log artifacts: $($iocResults.LogArtifacts.Count)" -Level "INFO"
    Write-ValidationLog "TOTAL IoCs DETECTED: $($iocResults.TotalFound)" -Level "SUCCESS"
    
    return $detected
}

function Validate-PathAccuracy {
    param([string]$TestName = "Path Accuracy Validation")
    
    Write-ValidationLog "=== Starting Path Accuracy Validation ===" -Level "INFO"
    Write-ValidationLog "Verifying that detection validator paths match actual simulation artifacts" -Level "INFO"
    
    # Check for actual extraction directory structure
    $extractionDirs = @(
        "$env:TEMP\nvidiadrivers",
        "$env:TEMP\nvidiadrivers\nvidiadrivers"
    )
    
    foreach ($dir in $extractionDirs) {
        if (Test-Path $dir) {
            Write-ValidationLog "[+] FOUND: Extraction directory - $dir" -Level "SUCCESS"
            # List contents
            try {
                $contents = Get-ChildItem $dir -ErrorAction SilentlyContinue
                foreach ($item in $contents) {
                    Write-ValidationLog "    Contents: $($item.Name) ($($item.GetType().Name))" -Level "INFO"
                }
            } catch {
                Write-ValidationLog "Could not list contents of $dir" -Level "WARNING"
            }
        } else {
            Write-ValidationLog "[-] NOT FOUND: Extraction directory - $dir" -Level "WARNING"
        }
    }
    
    # Check for actual driver files
    $driverPaths = @(
        "$env:TEMP\iqvw64.sys",
        "$env:TEMP\nvidiadrivers\iqvw64.sys",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\iqvw64.sys"
    )
    
    foreach ($path in $driverPaths) {
        if (Test-Path $path) {
            $file = Get-Item $path
            Write-ValidationLog "[+] FOUND: Driver file - $path ($($file.Length) bytes)" -Level "SUCCESS"
        } else {
            Write-ValidationLog "[-] NOT FOUND: Driver file - $path" -Level "INFO"
        }
    }
    
    # Check for actual VBS files
    $vbsPaths = @(
        "$env:TEMP\nvidiadrivers\install.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\install.vbs",
        "$env:TEMP\nvidiadrivers\driver_loader.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\driver_loader.vbs"
    )
    
    foreach ($path in $vbsPaths) {
        if (Test-Path $path) {
            $file = Get-Item $path
            Write-ValidationLog "[+] FOUND: VBS file - $path ($($file.Length) bytes)" -Level "SUCCESS"
        } else {
            Write-ValidationLog "[-] NOT FOUND: VBS file - $path" -Level "INFO"
        }
    }
    
    # Check for log files
    $logPatterns = @(
        "$env:TEMP\iqvw64_*.log",
        "$env:TEMP\*nvidia*.log",
        "$env:TEMP\byovd_*.log"
    )
    
    foreach ($pattern in $logPatterns) {
        try {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            if ($files) {
                foreach ($file in $files) {
                    Write-ValidationLog "[+] FOUND: Log file - $($file.FullName)" -Level "SUCCESS"
                }
            } else {
                Write-ValidationLog "[-] NOT FOUND: Log pattern - $pattern" -Level "INFO"
            }
        } catch {
            Write-ValidationLog "Error checking pattern $pattern - $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    Write-ValidationLog "Path accuracy validation completed" -Level "INFO"
}

function Validate-FailedTechniqueScenarios {
    param([string]$TestName = "Failed Technique Scenario Validation")
    
    Write-ValidationLog "=== Starting Failed Technique Scenario Validation ===" -Level "INFO"
    Write-ValidationLog "Checking for error logs, execution summaries, and partial technique artifacts" -Level "INFO"
    
    $failureResults = @{
        ErrorLogs = @()
        ExecutionSummaries = @()
        PartialArtifacts = @()
        TotalFound = 0
    }
    
    # Check for error logs from enhanced driver loader
    Write-ValidationLog "Checking for error logs..." -Level "INFO"
    
    $errorLogPattern = "$env:TEMP\iqvw64_errors_*.log"
    try {
        $errorLogs = Get-ChildItem $errorLogPattern -ErrorAction SilentlyContinue
        foreach ($log in $errorLogs) {
            $content = Get-Content $log -Head 20 -ErrorAction SilentlyContinue
            $failureResults.ErrorLogs += @{
                Path = $log.FullName
                Size = $log.Length
                LastModified = $log.LastWriteTime
                ErrorCount = ($content | Where-Object { $_ -like "*ERROR*" }).Count
                Preview = ($content -join "; ").Substring(0, [Math]::Min(200, ($content -join "; ").Length))
            }
            Write-ValidationLog "[+] ERROR LOG DETECTED: $($log.Name) with $($($content | Where-Object { $_ -like '*ERROR*' }).Count) errors" -Level "DETECTION"
        }
    } catch {
        Write-ValidationLog "Could not check error logs: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check for execution summaries with technique success/failure data
    Write-ValidationLog "Checking for execution summaries..." -Level "INFO"
    
    $summaryPattern = "$env:TEMP\iqvw64_execution_summary_*.txt"
    try {
        $summaryFiles = Get-ChildItem $summaryPattern -ErrorAction SilentlyContinue
        foreach ($summary in $summaryFiles) {
            $content = Get-Content $summary -ErrorAction SilentlyContinue
            $successCount = ($content | Where-Object { $_ -like "*SUCCESS*" }).Count
            $failedCount = ($content | Where-Object { $_ -like "*FAILED*" }).Count
            
            $failureResults.ExecutionSummaries += @{
                Path = $summary.FullName
                Size = $summary.Length
                LastModified = $summary.LastWriteTime
                SuccessfulTechniques = $successCount
                FailedTechniques = $failedCount
                TotalTechniques = $successCount + $failedCount
            }
            Write-ValidationLog "[+] EXECUTION SUMMARY DETECTED: $($summary.Name) - $successCount successful, $failedCount failed techniques" -Level "DETECTION"
        }
    } catch {
        Write-ValidationLog "Could not check execution summaries: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Check for partial technique artifacts (registry keys that might exist even if techniques partially failed)
    Write-ValidationLog "Checking for partial technique artifacts..." -Level "INFO"
    
    $partialRegistryKeys = @(
        "HKCU:\Software\Intel\Diagnostics",
        "HKCU:\Software\DriverTest\iqvw64"
    )
    
    foreach ($regPath in $partialRegistryKeys) {
        try {
            if (Test-Path $regPath) {
                $values = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $regValues = @()
                if ($values) {
                    $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                        $regValues += "$($_.Name)=$($_.Value)"
                    }
                }
                
                $failureResults.PartialArtifacts += @{
                    Type = "Registry"
                    Path = $regPath
                    Values = $regValues
                    LastModified = (Get-Item $regPath).LastWriteTime
                }
                Write-ValidationLog "[+] PARTIAL REGISTRY ARTIFACT: $regPath with $($regValues.Count) values" -Level "DETECTION"
            }
        } catch {
            Write-ValidationLog "Could not check registry path $regPath`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Calculate totals
    $failureResults.TotalFound = $failureResults.ErrorLogs.Count + 
                                 $failureResults.ExecutionSummaries.Count + 
                                 $failureResults.PartialArtifacts.Count
    
    $detected = $failureResults.TotalFound -gt 0
    
    # Create detailed result
    $details = @()
    if ($failureResults.ErrorLogs.Count -gt 0) {
        $details += "Error Logs: $($failureResults.ErrorLogs.Count)"
    }
    if ($failureResults.ExecutionSummaries.Count -gt 0) {
        $details += "Execution Summaries: $($failureResults.ExecutionSummaries.Count)"
    }
    if ($failureResults.PartialArtifacts.Count -gt 0) {
        $details += "Partial Artifacts: $($failureResults.PartialArtifacts.Count)"
    }
    
    $result = @{
        TestName = $TestName
        DetectionMethod = "Failed Technique Analysis"
        MitreTechnique = "Multiple"
        MitreTactic = "Multiple"
        Detected = $detected
        Details = "Total failure artifacts: $($failureResults.TotalFound) [$($details -join ', ')]"
        EventCount = $failureResults.TotalFound
        Timestamp = Get-Date
        FailureArtifacts = $failureResults
    }
    
    $script:TestResults += $result
    
    Write-ValidationLog "=== Failed Technique Scenario Validation Summary ===" -Level "INFO"
    Write-ValidationLog "Error logs found: $($failureResults.ErrorLogs.Count)" -Level "INFO"
    Write-ValidationLog "Execution summaries found: $($failureResults.ExecutionSummaries.Count)" -Level "INFO"
    Write-ValidationLog "Partial artifacts found: $($failureResults.PartialArtifacts.Count)" -Level "INFO"
    Write-ValidationLog "TOTAL FAILURE ARTIFACTS: $($failureResults.TotalFound)" -Level "SUCCESS"
    
    if ($detected) {
        Write-ValidationLog "[+] DETECTION: Failed technique scenarios provide valuable forensic data" -Level "DETECTION"
    } else {
        Write-ValidationLog "[-] NO FAILURE ARTIFACTS: No error logs or execution summaries found" -Level "WARNING"
    }
    
    return $detected
}

function Generate-DetectionReport {
    Write-ValidationLog "Generating detection validation report..." -Level "INFO"
    
    $totalTests = $script:TestResults.Count
    $detectedTests = ($script:TestResults | Where-Object { $_.Detected -eq $true }).Count
    $detectionRate = if ($totalTests -gt 0) { [math]::Round(($detectedTests / $totalTests) * 100, 2) } else { 0 }
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>BYOVD Detection Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .detected { color: #27ae60; font-weight: bold; }
        .not-detected { color: #e74c3c; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 10px; text-align: left; }
        th { background-color: #34495e; color: white; }
        .score-good { background-color: #d5f4e6; }
        .score-medium { background-color: #fef9e7; }
        .score-poor { background-color: #fadbd8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>BYOVD Detection Validation Report</h1>
        <p>Bring Your Own Vulnerable Driver - Security Controls Assessment</p>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr><td><strong>Total Tests:</strong></td><td>$totalTests</td></tr>
            <tr><td><strong>Detected:</strong></td><td class="detected">$detectedTests</td></tr>
            <tr><td><strong>Not Detected:</strong></td><td class="not-detected">$($totalTests - $detectedTests)</td></tr>
            <tr><td><strong>Detection Rate:</strong></td><td>$detectionRate%</td></tr>
            <tr><td><strong>Test Duration:</strong></td><td>$([math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 2)) minutes</td></tr>
            <tr><td><strong>Admin Privileges:</strong></td><td>$(if(Test-AdminPrivileges){'Yes'}else{'No'})</td></tr>
        </table>
    </div>
    
    <div class="summary">
        <h3>Overall Assessment</h3>
        <p><strong>Detection Rate:</strong> $detectionRate%</p>
        <p><strong>Status:</strong> $(if($detectionRate -ge 80){'GOOD'}elseif($detectionRate -ge 60){'MEDIUM'}else{'POOR'})</p>
        <p><strong>Recommendation:</strong> $(if($detectionRate -ge 80){'Maintain controls'}elseif($detectionRate -ge 60){'Enhance monitoring'}else{'Immediate attention required'})</p>
    </div>
    
    <h2>Detailed Test Results</h2>
    <table>
        <tr>
            <th>Test Name</th>
            <th>MITRE Technique</th>
            <th>Detection Method</th>
            <th>Status</th>
            <th>Details</th>
            <th>Timestamp</th>
        </tr>
"@
    
    foreach ($result in $script:TestResults) {
        $statusClass = if ($result.Detected) { "detected" } else { "not-detected" }
        $statusText = if ($result.Detected) { "[+] DETECTED" } else { "[-] NOT DETECTED" }
        
        $mitreInfo = if ($result.MitreTechnique) { "$($result.MitreTechnique) ($($result.MitreTactic))" } else { "-" }
        $htmlReport += @"
        <tr>
            <td>$($result.TestName)</td>
            <td>$mitreInfo</td>
            <td>$($result.DetectionMethod)</td>
            <td class="$statusClass">$statusText</td>
            <td>$($result.Details)</td>
            <td>$($result.Timestamp.ToString("HH:mm:ss"))</td>
        </tr>
"@
    }
    
    $htmlReport += @"
    </table>
    
    <h2>MITRE ATT&CK Coverage</h2>
    <div class="summary">
        <p>This validation tested detection capabilities for the following BYOVD-related techniques:</p>
        <ul>
            <li><strong>T1068:</strong> Exploitation for Privilege Escalation (CVE-2015-2291 Intel Ethernet)</li>
            <li><strong>T1014:</strong> Rootkit (Kernel-level compromise and hiding)</li>
            <li><strong>T1543.003:</strong> Windows Service (Driver service persistence)</li>
            <li><strong>T1547.006:</strong> Kernel Modules and Extensions (BYOVD installation)</li>
            <li><strong>T1562.001:</strong> Impair Defenses (Security software termination)</li>
            <li><strong>T1003:</strong> OS Credential Dumping (LSASS access preparation)</li>
            <li><strong>T1055:</strong> Process Injection (Process hollowing preparation)</li>
            <li><strong>T1059.005:</strong> Command and Scripting Interpreter: Visual Basic</li>
            <li><strong>T1112:</strong> Modify Registry (Driver and persistence modifications)</li>
            <li><strong>T1070.004:</strong> Indicator Removal (File operations and cleanup)</li>
            <li><strong>T1105:</strong> Ingress Tool Transfer (Driver package delivery)</li>
        </ul>
    </div>
    
    <h2>Recommendations</h2>
    <div class="summary">
        <h3>Immediate Actions:</h3>
        <ul>
            <li>Review undetected techniques and implement additional monitoring</li>
            <li>Consider deploying Sysmon with comprehensive configuration</li>
            <li>Enable advanced audit policies for file and registry monitoring</li>
            <li>Regularly test detection capabilities with BYOVD simulations</li>
            <li>Train security team on BYOVD attack patterns and indicators</li>
            <li>Implement driver blocklist and signature verification</li>
        </ul>
        
        <h3>Long-term Improvements:</h3>
        <ul>
            <li>Deploy behavioral analysis tools for kernel-level activity monitoring</li>
            <li>Implement memory integrity features (HVCI, Credential Guard)</li>
            <li>Regular vulnerability assessments of installed drivers</li>
            <li>Automated threat hunting for BYOVD indicators</li>
        </ul>
    </div>
    
    <div class="summary">
        <p><strong>Report Generated By:</strong> BYOVD Detection Validator v1.0</p>
        <p><strong>Author:</strong> Crimson7 Research Team</p>
        <p><strong>Log File:</strong> $script:ValidationLog</p>
    </div>
</body>
</html>
"@
    
    Set-Content -Path $OutputPath -Value $htmlReport
    Write-ValidationLog "Detection report saved: $OutputPath" -Level "SUCCESS"
    
    # Generate MITRE ATT&CK detection summary
    Generate-MitreAttackSummary
    
    # Generate detection rules based on findings
    Generate-DetectionRules
    
    return $OutputPath
}

function Generate-MitreAttackSummary {
    $mitreSummaryPath = "$env:TEMP\byovd_mitre_attack_detection_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    # Create detailed MITRE ATT&CK mapping
    $mitreResults = @{
        TestSession = @{
            StartTime = $script:StartTime
            EndTime = Get-Date
            Duration = ((Get-Date) - $script:StartTime).TotalMinutes
            TotalTests = $script:TestResults.Count
            DetectedTests = ($script:TestResults | Where-Object { $_.Detected }).Count
        }
        TechniquesDetected = @()
        TechniquesNotDetected = @()
        DetailedResults = @()
    }
    
    foreach ($result in $script:TestResults) {
        $detailEntry = @{
            Timestamp = $result.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
            TestName = $result.TestName
            MitreTechnique = $result.MitreTechnique
            MitreTactic = $result.MitreTactic
            DetectionMethod = $result.DetectionMethod
            Detected = $result.Detected
            Details = $result.Details
        }
        
        $mitreResults.DetailedResults += $detailEntry
        
        if ($result.MitreTechnique) {
            $techniqueEntry = @{
                Technique = $result.MitreTechnique
                Tactic = $result.MitreTactic
                TestName = $result.TestName
                Detected = $result.Detected
                Timestamp = $result.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            if ($result.Detected) {
                $mitreResults.TechniquesDetected += $techniqueEntry
            } else {
                $mitreResults.TechniquesNotDetected += $techniqueEntry
            }
        }
    }
    
    # Convert to JSON and save
    $jsonOutput = $mitreResults | ConvertTo-Json -Depth 10
    Set-Content -Path $mitreSummaryPath -Value $jsonOutput
    
    Write-ValidationLog "MITRE ATT&CK detection summary saved: $mitreSummaryPath" -Level "SUCCESS"
    
    # Display summary
    Write-ValidationLog "=== MITRE ATT&CK DETECTION SUMMARY ===" -Level "SUCCESS"
    Write-ValidationLog "Techniques Detected: $($mitreResults.TechniquesDetected.Count)" -Level "SUCCESS"
    Write-ValidationLog "Techniques Not Detected: $($mitreResults.TechniquesNotDetected.Count)" -Level "WARNING"
    
    if ($mitreResults.TechniquesDetected.Count -gt 0) {
        Write-ValidationLog "Detected Techniques:" -Level "SUCCESS"
        foreach ($technique in $mitreResults.TechniquesDetected) {
            Write-ValidationLog "  [+] $($technique.Technique) - $($technique.TestName)" -Level "DETECTION"
        }
    }
    
    if ($mitreResults.TechniquesNotDetected.Count -gt 0) {
        Write-ValidationLog "Undetected Techniques (Security Gaps):" -Level "WARNING"
        foreach ($technique in $mitreResults.TechniquesNotDetected) {
            Write-ValidationLog "  [-] $($technique.Technique) - $($technique.TestName)" -Level "WARNING"
        }
    }
    
    return $mitreSummaryPath
}

function Generate-DetectionRules {
    Write-ValidationLog "Generating detection rules based on test results..." -Level "INFO"
    
    $rulesPath = "$env:TEMP\byovd_detection_rules_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -Path $rulesPath -ItemType Directory -Force | Out-Null
    
    # Generate KQL queries for Microsoft Sentinel
    $kqlQueries = @"
// BYOVD Detection Rules - Generated from Validation Tests
// Generated: $(Get-Date)

// Rule 1: Suspicious VBS Execution from Temp Directory
let SuspiciousVBSExecution = 
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where Process contains "wscript.exe"
| where CommandLine contains "temp" or CommandLine contains "tmp"
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName;

// Rule 2: PowerShell Archive Extraction
let SuspiciousPowerShellArchive = 
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine contains "Expand-Archive"
| where ProcessCommandLine contains "temp" or ProcessCommandLine contains "nvidiadrivers"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine;

// Rule 3: Registry Modifications (BYOVD Indicators)
let BYOVDRegistryModifications = 
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4657
| where ObjectName contains "BYOVD" or ObjectName contains "BYOVDNVIDIATest"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, ObjectValueName;

// Rule 4: Windows Defender Events
let DefenderEvents = 
Event
| where TimeGenerated > ago(24h)
| where Source == "Microsoft-Windows-Windows Defender"
| where EventID in (1116, 1117, 5001, 5007)
| project TimeGenerated, Computer, EventID, RenderedDescription;

// Union all detection rules
SuspiciousVBSExecution
| union SuspiciousPowerShellArchive
| union BYOVDRegistryModifications  
| union DefenderEvents
| sort by TimeGenerated desc
"@
    
    Set-Content -Path "$rulesPath\sentinel_kql_rules.kql" -Value $kqlQueries
    Write-ValidationLog "KQL rules saved: $rulesPath\sentinel_kql_rules.kql" -Level "SUCCESS"
    
    # Generate Splunk SPL queries
    $splunkQueries = @"
# BYOVD Detection Rules - Splunk SPL
# Generated: $(Get-Date)

# Rule 1: Suspicious VBS Execution
index=windows source="WinEventLog:Security" EventCode=4688 Image="*wscript.exe*" CommandLine="*temp*"
| table _time, host, user, Image, CommandLine, ParentImage
| sort -_time

# Rule 2: PowerShell Archive Operations
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103 Message="*Expand-Archive*"
| table _time, host, user, Message
| sort -_time

# Rule 3: Registry BYOVD Indicators
index=windows source="WinEventLog:Security" EventCode=4657 ObjectName="*BYOVD*"
| table _time, host, user, ObjectName, ObjectValueName
| sort -_time

# Rule 4: Windows Defender Alerts
index=windows source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode IN (1116,1117,5001,5007)
| table _time, host, EventCode, Message
| sort -_time
"@
    
    Set-Content -Path "$rulesPath\splunk_spl_rules.spl" -Value $splunkQueries
    Write-ValidationLog "Splunk rules saved: $rulesPath\splunk_spl_rules.spl" -Level "SUCCESS"
    
    # Generate YARA rules for file artifacts
    $yaraRules = @"
/*
BYOVD Detection Rules - YARA
Generated: $(Get-Date)
*/

rule BYOVD_NVIDIA_Package {
    meta:
        description = "Detects BYOVD NVIDIA driver package indicators"
        author = "Crimson7 Research Team"
        date = "$(Get-Date -Format 'yyyy-MM-dd')"
        mitre_attack = "T1105"
        
    strings:
        `$filename1 = "nvidiadrivers.zip"
        `$filename2 = "install.vbs" 
        `$filename3 = "driver_loader.vbs"
        `$registry1 = "BYOVDNVIDIATest"
        `$registry2 = "VBSBYOVDTest"
        
    condition:
        any of (`$filename*) or any of (`$registry*)
}

rule BYOVD_VBS_Script {
    meta:
        description = "Detects BYOVD VBS script execution indicators"
        author = "Crimson7 Research Team" 
        date = "$(Get-Date -Format 'yyyy-MM-dd')"
        mitre_attack = "T1059.005"
        
    strings:
        `$vbs1 = "WScript.Shell"
        `$vbs2 = "CreateObject"
        `$vbs3 = "BYOVD"
        `$vbs4 = "nvidia"
        
    condition:
        all of (`$vbs1, `$vbs2) and any of (`$vbs3, `$vbs4)
}
"@
    
    Set-Content -Path "$rulesPath\byovd_detection.yar" -Value $yaraRules
    Write-ValidationLog "YARA rules saved: $rulesPath\byovd_detection.yar" -Level "SUCCESS"
    
    # Generate Sigma rules
    $sigmaRules = @"
title: BYOVD VBS Script Execution
id: $(New-Guid)
status: experimental
description: Detects suspicious VBS script execution from temp directories (BYOVD indicator)
author: Crimson7 Research Team
date: $(Get-Date -Format 'yyyy/MM/dd')
references:
    - https://attack.mitre.org/techniques/T1059/005/
tags:
    - attack.execution
    - attack.t1059.005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        ProcessName: '*wscript.exe'
        CommandLine: '*temp*'
    condition: selection
falsepositives:
    - Legitimate VBS scripts executed from temp directories
level: medium

---

title: BYOVD PowerShell Archive Extraction
id: $(New-Guid)
status: experimental  
description: Detects PowerShell archive extraction operations (BYOVD delivery method)
author: Crimson7 Research Team
date: $(Get-Date -Format 'yyyy/MM/dd')
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4103
        Message: '*Expand-Archive*'
    filter:
        Message: '*nvidiadrivers*'
    condition: selection and filter
falsepositives:
    - Legitimate PowerShell archive operations
level: medium
"@
    
    Set-Content -Path "$rulesPath\sigma_rules.yml" -Value $sigmaRules
    Write-ValidationLog "Sigma rules saved: $rulesPath\sigma_rules.yml" -Level "SUCCESS"
    
    Write-ValidationLog "Detection rules generation completed: $rulesPath" -Level "SUCCESS"
    return $rulesPath
}

# Parameter validation
if (-not ($TestDriverInstallation -or $TestProcessTermination -or $TestVBSExecution -or $TestRegistryModification -or $TestFileOperations -or $TestWindowsDefender -or $TestPowerShellLogging -or $TestAttackChainIoCs -or $TestFailedTechniques -or $TestAllDetections)) {
    Write-Host "No test selected. Use -TestAllDetections to run all tests or specify individual tests:" -ForegroundColor Yellow
    Write-Host "  -TestDriverInstallation" -ForegroundColor Cyan
    Write-Host "  -TestProcessTermination" -ForegroundColor Cyan
    Write-Host "  -TestVBSExecution" -ForegroundColor Cyan
    Write-Host "  -TestRegistryModification" -ForegroundColor Cyan
    Write-Host "  -TestFileOperations" -ForegroundColor Cyan
    Write-Host "  -TestWindowsDefender" -ForegroundColor Cyan
    Write-Host "  -TestPowerShellLogging" -ForegroundColor Cyan
    Write-Host "  -TestAttackChainIoCs" -ForegroundColor Cyan
    Write-Host "  -TestFailedTechniques" -ForegroundColor Cyan
    Write-Host "Example: .\detection_validator.ps1 -TestAllDetections" -ForegroundColor Green
    exit
}

# Main execution
Write-ValidationLog "BYOVD Detection Validator Started" -Level "INFO"
Write-ValidationLog "Test Duration: $TestDurationMinutes minutes" -Level "INFO"
Write-ValidationLog "Administrative Privileges: $(if(Test-AdminPrivileges){'Yes'}else{'No'})" -Level "INFO"

# Run selected tests
if ($TestAllDetections) {
    $TestDriverInstallation = $true
    $TestProcessTermination = $true
    $TestVBSExecution = $true
    $TestRegistryModification = $true
    $TestFileOperations = $true
    $TestWindowsDefender = $true
    $TestPowerShellLogging = $true
    $TestAttackChainIoCs = $true
    $TestFailedTechniques = $true
}

if ($TestDriverInstallation) {
    Invoke-DriverInstallationTest
}

if ($TestProcessTermination) {
    Invoke-ProcessTerminationTest
}

if ($TestVBSExecution) {
    Invoke-VBSExecutionTest
}

if ($TestRegistryModification) {
    Invoke-RegistryModificationTest
}

if ($TestFileOperations) {
    Invoke-FileOperationsTest
}

if ($TestWindowsDefender) {
    Test-WindowsDefenderDetection -TestName "Windows Defender Status Check" -MitreTechnique "T1562.001" -MitreTactic "Defense Evasion"
}

if ($TestPowerShellLogging) {
    Test-PowerShellLoggingDetection -TestName "PowerShell Activity Detection" -MitreTechnique "T1059.001" -MitreTactic "Execution"
}

if ($TestAttackChainIoCs) {
    Validate-AttackChainIoCs
}

if ($TestFailedTechniques) {
    Validate-PathAccuracy
    Validate-FailedTechniqueScenarios
}

# Cleanup any remaining test processes
Write-ValidationLog "Cleaning up test processes..." -Level "INFO"
$testProcessNames = @("notepad", "calc", "wscript")
foreach ($procName in $testProcessNames) {
    $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        try {
            # Only kill processes started during our test (check start time)
            if ($proc.StartTime -gt $script:StartTime) {
                Stop-Process -Id $proc.Id -Force
                Write-ValidationLog "Cleaned up test process: $procName (PID: $($proc.Id))" -Level "INFO"
            }
        } catch {
            Write-ValidationLog "Could not cleanup process: $procName" -Level "WARNING"
        }
    }
}

# Wait for events to be processed (reduced time)
Write-ValidationLog "Waiting for event processing..." -Level "INFO"
Start-Sleep -Seconds 5

# Generate report
if ($GenerateReport) {
    $reportPath = Generate-DetectionReport
    Write-ValidationLog "Opening detection report..." -Level "INFO"
    try {
        Start-Process $reportPath
    } catch {
        Write-ValidationLog "Could not open report automatically: $reportPath" -Level "WARNING"
    }
}

Write-ValidationLog "BYOVD Detection Validation Completed" -Level "SUCCESS"
Write-ValidationLog "Total Tests: $($script:TestResults.Count)" -Level "INFO"
Write-ValidationLog "Detected: $(($script:TestResults | Where-Object { $_.Detected }).Count)" -Level "INFO"
Write-ValidationLog "Log File: $script:ValidationLog" -Level "INFO"