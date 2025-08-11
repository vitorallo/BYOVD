# BYOVD Cleanup Verifier
# Tool to verify complete cleanup of BYOVD simulation artifacts
# Author: Crimson7 Threat Intelligence Team

param(
    [switch]$FullScan = $false,
    [switch]$DeepScan = $false,
    [switch]$QuickScan = $true,
    [switch]$RemoveFoundArtifacts = $false,
    [switch]$GenerateReport = $true,
    [string]$OutputPath = "$env:TEMP\byovd_cleanup_report.txt",
    [string]$ScanPath = $env:TEMP
)

# Global variables
$script:FoundArtifacts = @()
$script:ScanResults = @()
$script:StartTime = Get-Date
$script:CleanupLog = "$env:TEMP\byovd_cleanup_verification_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-CleanupLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "FOUND" { "Cyan" }
            default { "White" }
        }
    )
    
    Add-Content -Path $script:CleanupLog -Value $logEntry
}

function Get-BYOVDArtifactPatterns {
    return @{
        "DriverFiles" = @(
            "iqvw64.sys", "iqvw64_test.sys", "test_driver.sys",
            "smuol.sys", "viragt64.sys", "dbutil_2_3.sys",
            "*test*driver*.sys", "*byovd*.sys", "*vulnerable*.sys",
            "*intel*eth*.sys", "*diagnostics*.sys", "*mock*.sys"
        )
        "VBSFiles" = @(
            "update.vbs", "driver_loader.vbs", "*byovd*.vbs",
            "*driver*.vbs", "*test*.vbs", "*nvidia*.vbs"
        )
        "LogFiles" = @(
            "*byovd*.log", "*driver*.log", "*test*.log",
            "vbs_driver_test.log", "driver_loader.log",
            "*byovd_simulation*.log", "*validation*.log",
            "*iqvw64*.log", "*nvidia_install*.log", "*exploit_artifacts*.txt",
            "iqvw64_errors_*.log", "iqvw64_execution_summary_*.txt"
        )
        "ConfigFiles" = @(
            "*byovd*.ini", "*driver*.ini", "config.ini",
            "*test*.cfg", "*simulation*.conf"
        )
        "ArchiveFiles" = @(
            "nvidiadrivers.zip", "*driver*.zip", "*nvidia*.zip",
            "test_driver_package.zip", "*byovd*.zip"
        )
        "RegistryBackups" = @(
            "*registry*.reg", "*backup*.reg", "*dse*.reg",
            "*byovd*.reg", "*test*.reg"
        )
        "MemoryDumps" = @(
            "*lsass*.dmp", "*memory*.dmp", "*credential*.dmp",
            "*dump*.dmp", "*extract*.dmp"
        )
        "TempFiles" = @(
            "*byovd*.tmp", "*driver*.tmp", "*test*.tmp",
            "uac_test.txt", "*admin_test*.tmp"
        )
        "ArtifactFiles" = @(
            "*artifacts*.txt", "*detection*.txt", "*ioc*.txt",
            "*post_exploit*.txt", "*masquerade*.txt"
        )
        "PowerShellFiles" = @(
            "*byovd*.ps1", "*driver*.ps1", "*test*.ps1",
            "powershell_helper.ps1", "*simulation*.ps1"
        )
    }
}

function Get-BYOVDRegistryPaths {
    return @(
        "HKCU:\Software\BYOVDTest",
        "HKCU:\Software\VBSBYOVDTest",
        "HKCU:\Software\BYOVDMasqueradeTest",
        "HKCU:\Software\BYOVDDetectionTest",
        "HKCU:\Software\Intel\Diagnostics",
        "HKCU:\Software\BYOVDNVIDIATest",
        "HKCU:\Software\DriverTest",
        "HKCU:\Software\NVIDIA Corporation\NvContainer",
        "HKLM:\SOFTWARE\BYOVDTest",
        "HKLM:\SYSTEM\CurrentControlSet\Services\*BYOVD*",
        "HKLM:\SYSTEM\CurrentControlSet\Services\*TestDriver*",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VulnEthDriver",
        "HKLM:\SYSTEM\CurrentControlSet\Services\BYOVDTestDriver",
        "HKLM:\SYSTEM\CurrentControlSet\Services\iqvw64",
        "HKLM:\SYSTEM\CurrentControlSet\Services\NVIDIAEthDiag"
    )
}

function Scan-FileSystemArtifacts {
    param([string]$Path, [hashtable]$Patterns, [bool]$Recursive = $true)
    
    Write-CleanupLog "Scanning filesystem for BYOVD artifacts in: $Path" -Level "INFO"
    
    $foundFiles = @()
    
    foreach ($category in $Patterns.Keys) {
        Write-CleanupLog "Scanning for $category..." -Level "INFO"
        
        foreach ($pattern in $Patterns[$category]) {
            try {
                if ($Recursive) {
                    $files = Get-ChildItem -Path $Path -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue
                } else {
                    $files = Get-ChildItem -Path $Path -Filter $pattern -File -ErrorAction SilentlyContinue
                }
                
                foreach ($file in $files) {
                    $artifact = @{
                        Type = "File"
                        Category = $category
                        Path = $file.FullName
                        Name = $file.Name
                        Size = $file.Length
                        Created = $file.CreationTime
                        Modified = $file.LastWriteTime
                        Pattern = $pattern
                    }
                    
                    $foundFiles += $artifact
                    $script:FoundArtifacts += $artifact
                    
                    Write-CleanupLog "FOUND: $category - $($file.FullName)" -Level "FOUND"
                }
            } catch {
                Write-CleanupLog "Error scanning pattern '$pattern': $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    
    return $foundFiles
}

function Scan-RegistryArtifacts {
    Write-CleanupLog "Scanning registry for BYOVD artifacts..." -Level "INFO"
    
    $foundRegistry = @()
    $registryPaths = Get-BYOVDRegistryPaths
    
    foreach ($regPath in $registryPaths) {
        try {
            # Handle wildcard paths
            if ($regPath -match '\*') {
                $basePath = $regPath -replace '\\\*.*$', ''
                $pattern = ($regPath -split '\\')[-1]
                
                if (Test-Path $basePath) {
                    $keys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $pattern }
                    
                    foreach ($key in $keys) {
                        $artifact = @{
                            Type = "Registry"
                            Category = "RegistryKey"
                            Path = $key.PSPath
                            Name = $key.Name
                            Pattern = $pattern
                            Values = @()
                        }
                        
                        # Get registry values
                        try {
                            $values = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            if ($values) {
                                $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                                    $artifact.Values += @{Name = $_.Name; Value = $_.Value}
                                }
                            }
                        } catch {}
                        
                        $foundRegistry += $artifact
                        $script:FoundArtifacts += $artifact
                        
                        Write-CleanupLog "FOUND: Registry Key - $($key.Name)" -Level "FOUND"
                    }
                }
            } else {
                # Direct path check
                if (Test-Path $regPath) {
                    $artifact = @{
                        Type = "Registry"
                        Category = "RegistryKey"
                        Path = $regPath
                        Name = (Split-Path $regPath -Leaf)
                        Pattern = "Direct"
                        Values = @()
                    }
                    
                    # Get registry values
                    try {
                        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                                $artifact.Values += @{Name = $_.Name; Value = $_.Value}
                            }
                        }
                    } catch {}
                    
                    $foundRegistry += $artifact
                    $script:FoundArtifacts += $artifact
                    
                    Write-CleanupLog "FOUND: Registry Key - $regPath" -Level "FOUND"
                }
            }
        } catch {
            Write-CleanupLog "Error checking registry path '$regPath': $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    return $foundRegistry
}

function Scan-ServiceArtifacts {
    Write-CleanupLog "Scanning for BYOVD-related services..." -Level "INFO"
    
    $foundServices = @()
    $servicePatterns = @(
        "*BYOVD*", "*Test*Driver*", "*Vuln*", "*Intel*Eth*",
        "*Driver*Test*", "*Mock*", "*Simulation*", "iqvw64",
        "NVIDIAEthDiag", "*Diagnostics*", "*CVE*"
    )
    
    foreach ($pattern in $servicePatterns) {
        try {
            $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
            
            foreach ($service in $services) {
                $artifact = @{
                    Type = "Service"
                    Category = "WindowsService"
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                    Pattern = $pattern
                }
                
                # Get service binary path
                try {
                    $serviceConfig = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
                    if ($serviceConfig) {
                        $artifact.BinaryPath = $serviceConfig.PathName
                    }
                } catch {}
                
                $foundServices += $artifact
                $script:FoundArtifacts += $artifact
                
                Write-CleanupLog "FOUND: Service - $($service.Name) ($($service.Status))" -Level "FOUND"
            }
        } catch {
            Write-CleanupLog "Error scanning services with pattern '$pattern': $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    return $foundServices
}

function Scan-EventLogArtifacts {
    Write-CleanupLog "Scanning event logs for BYOVD artifacts..." -Level "INFO"
    
    $foundEvents = @()
    $startTime = (Get-Date).AddDays(-1)  # Last 24 hours
    
    # BYOVD-related event sources
    $eventSources = @("BYOVD-Test", "BYOVD-Simulation", "VBS-Test")
    
    foreach ($source in $eventSources) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = "Application"
                StartTime = $startTime
            } -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*$source*" }
            
            foreach ($event in $events) {
                $artifact = @{
                    Type = "EventLog"
                    Category = "ApplicationEvent"
                    EventID = $event.Id
                    Source = $event.ProviderName
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                }
                
                $foundEvents += $artifact
                $script:FoundArtifacts += $artifact
                
                Write-CleanupLog "FOUND: Event Log - ID $($event.Id) from $($event.ProviderName)" -Level "FOUND"
            }
        } catch {
            Write-CleanupLog "Error scanning events for source '$source': $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    return $foundEvents
}

function Remove-FoundArtifacts {
    Write-CleanupLog "Attempting to remove found BYOVD artifacts..." -Level "WARNING"
    
    $removedCount = 0
    $failedCount = 0
    
    foreach ($artifact in $script:FoundArtifacts) {
        try {
            switch ($artifact.Type) {
                "File" {
                    if (Test-Path $artifact.Path) {
                        Remove-Item $artifact.Path -Force
                        Write-CleanupLog "REMOVED: File - $($artifact.Path)" -Level "SUCCESS"
                        $removedCount++
                    }
                }
                "Registry" {
                    if (Test-Path $artifact.Path) {
                        Remove-Item $artifact.Path -Recurse -Force
                        Write-CleanupLog "REMOVED: Registry - $($artifact.Path)" -Level "SUCCESS"
                        $removedCount++
                    }
                }
                "Service" {
                    $service = Get-Service -Name $artifact.Name -ErrorAction SilentlyContinue
                    if ($service) {
                        if ($service.Status -eq "Running") {
                            Stop-Service -Name $artifact.Name -Force
                        }
                        # Note: Removing services requires sc delete command with admin privileges
                        Write-CleanupLog "Service found but removal requires manual action: $($artifact.Name)" -Level "WARNING"
                    }
                }
                "EventLog" {
                    Write-CleanupLog "Event log entries cannot be individually removed: Event ID $($artifact.EventID)" -Level "WARNING"
                }
            }
        } catch {
            Write-CleanupLog "FAILED to remove $($artifact.Type): $($artifact.Name) - $($_.Exception.Message)" -Level "ERROR"
            $failedCount++
        }
    }
    
    Write-CleanupLog "Cleanup summary: $removedCount removed, $failedCount failed" -Level "INFO"
    return @{Removed = $removedCount; Failed = $failedCount}
}

function Generate-CleanupReport {
    Write-CleanupLog "Generating cleanup verification report..." -Level "INFO"
    
    $totalArtifacts = $script:FoundArtifacts.Count
    $artifactsByType = $script:FoundArtifacts | Group-Object Type
    $artifactsByCategory = $script:FoundArtifacts | Group-Object Category
    
    $reportContent = @"
BYOVD Cleanup Verification Report
=================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Scan Type: $(if($FullScan){'Full Scan'}elseif($DeepScan){'Deep Scan'}else{'Quick Scan'})
Scan Path: $ScanPath
Scan Duration: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)) seconds

EXECUTIVE SUMMARY
================
Total Artifacts Found: $totalArtifacts
Cleanup Status: $(if($totalArtifacts -eq 0){'[+] CLEAN - No BYOVD artifacts detected'}else{'[!] ARTIFACTS FOUND - Cleanup required'})

ARTIFACTS BY TYPE
================
"@
    
    if ($artifactsByType) {
        foreach ($typeGroup in $artifactsByType) {
            $reportContent += "`n$($typeGroup.Name): $($typeGroup.Count) items`n"
            foreach ($artifact in $typeGroup.Group) {
                $reportContent += "  - $($artifact.Name)"
                if ($artifact.Path) { $reportContent += " ($($artifact.Path))" }
                $reportContent += "`n"
            }
        }
    } else {
        $reportContent += "`nNo artifacts found.`n"
    }
    
    $reportContent += @"

ARTIFACTS BY CATEGORY
====================
"@
    
    if ($artifactsByCategory) {
        foreach ($categoryGroup in $artifactsByCategory) {
            $reportContent += "`n$($categoryGroup.Name): $($categoryGroup.Count) items`n"
        }
    }
    
    $reportContent += @"

DETAILED FINDINGS
================
"@
    
    if ($totalArtifacts -gt 0) {
        foreach ($artifact in $script:FoundArtifacts) {
            $reportContent += "`nType: $($artifact.Type)`n"
            $reportContent += "Category: $($artifact.Category)`n"
            $reportContent += "Name: $($artifact.Name)`n"
            if ($artifact.Path) { $reportContent += "Path: $($artifact.Path)`n" }
            if ($artifact.Size) { $reportContent += "Size: $($artifact.Size) bytes`n" }
            if ($artifact.Created) { $reportContent += "Created: $($artifact.Created)`n" }
            if ($artifact.Modified) { $reportContent += "Modified: $($artifact.Modified)`n" }
            if ($artifact.Pattern) { $reportContent += "Matched Pattern: $($artifact.Pattern)`n" }
            $reportContent += "$(('-' * 50))`n"
        }
    } else {
        $reportContent += "`nNo artifacts found - system appears clean.`n"
    }
    
    $reportContent += @"

CLEANUP RECOMMENDATIONS
=======================
"@
    
    if ($totalArtifacts -gt 0) {
        $reportContent += @"

IMMEDIATE ACTIONS REQUIRED:
1. Review all found artifacts for legitimacy
2. Remove confirmed BYOVD test artifacts
3. Check for any production systems affected
4. Verify security controls are functioning

FILE CLEANUP:
- Remove test driver files (*.sys files in temp directories)
- Delete VBS scripts used for simulation
- Clear log files from testing activities
- Remove temporary configuration files

REGISTRY CLEANUP:
- Delete test registry keys under HKCU\Software\BYOVD*
- Remove any test service registrations
- Clean up driver-related test entries

SERVICE CLEANUP:
- Stop and remove test services (requires admin privileges)
- Verify no production services were affected
- Check service configurations for anomalies

EVENT LOG CLEANUP:
- Consider clearing application logs if needed
- Review security logs for any anomalies
- Document any legitimate events for future reference

VERIFICATION:
- Re-run this tool after cleanup to verify removal
- Perform additional scans on other systems
- Review backup systems for artifacts
"@
    } else {
        $reportContent += @"

[+] SYSTEM CLEAN
No BYOVD artifacts detected. The system appears to be properly cleaned up.

MAINTENANCE RECOMMENDATIONS:
1. Run periodic cleanup verification scans
2. Maintain documentation of legitimate drivers
3. Monitor for unexpected driver installations
4. Keep driver blocklists updated
5. Regular security assessments
"@
    }
    
    $reportContent += @"

TECHNICAL DETAILS
================
Scan Patterns Used:
$(foreach($category in (Get-BYOVDArtifactPatterns).Keys) {
    "`n$category`: $(((Get-BYOVDArtifactPatterns)[$category]) -join ', ')"
})

Registry Paths Checked:
$(foreach($path in (Get-BYOVDRegistryPaths)) {
    "`n- $path"
})

Generated by: BYOVD Cleanup Verifier v1.0
Author: Crimson7 Threat Intelligence Team
Log File: $script:CleanupLog
"@
    
    Set-Content -Path $OutputPath -Value $reportContent
    Write-CleanupLog "Cleanup report saved: $OutputPath" -Level "SUCCESS"
    
    return $OutputPath
}

# Main execution
Write-CleanupLog "BYOVD Cleanup Verifier Started" -Level "INFO"
Write-CleanupLog "Scan Mode: $(if($FullScan){'Full'}elseif($DeepScan){'Deep'}else{'Quick'})" -Level "INFO"
Write-CleanupLog "Target Path: $ScanPath" -Level "INFO"

# Configure scan parameters
$patterns = Get-BYOVDArtifactPatterns
$scanPaths = @($ScanPath)

if ($FullScan) {
    # Add additional paths for full scan
    $scanPaths += @(
        $env:USERPROFILE,
        "$env:SYSTEMROOT\System32\drivers",
        "$env:PROGRAMFILES",
        "${env:PROGRAMFILES(x86)}"
    )
    Write-CleanupLog "Full scan mode - scanning multiple locations" -Level "INFO"
}

if ($DeepScan) {
    # Add even more paths for deep scan
    $scanPaths += @(
        "$env:SYSTEMROOT\Temp",
        "$env:ALLUSERSPROFILE",
        "$env:LOCALAPPDATA"
    )
    Write-CleanupLog "Deep scan mode - comprehensive filesystem scan" -Level "INFO"
}

# Perform scans
foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        Write-CleanupLog "Scanning path: $path" -Level "INFO"
        $recursive = $FullScan -or $DeepScan
        Scan-FileSystemArtifacts -Path $path -Patterns $patterns -Recursive $recursive
    } else {
        Write-CleanupLog "Skipping non-existent path: $path" -Level "WARNING"
    }
}

# Scan registry
Scan-RegistryArtifacts

# Scan services
Scan-ServiceArtifacts

# Scan event logs
Scan-EventLogArtifacts

# Remove artifacts if requested
if ($RemoveFoundArtifacts -and $script:FoundArtifacts.Count -gt 0) {
    $removalResult = Remove-FoundArtifacts
    Write-CleanupLog "Removal completed: $($removalResult.Removed) removed, $($removalResult.Failed) failed" -Level "INFO"
}

# Generate report
if ($GenerateReport) {
    $reportPath = Generate-CleanupReport
    Write-CleanupLog "Opening cleanup report..." -Level "INFO"
    try {
        Start-Process "notepad.exe" -ArgumentList $reportPath
    } catch {
        Write-CleanupLog "Could not open report automatically: $reportPath" -Level "WARNING"
    }
}

# Summary
$totalArtifacts = $script:FoundArtifacts.Count
Write-CleanupLog "BYOVD Cleanup Verification Completed" -Level "SUCCESS"
Write-CleanupLog "Total Artifacts Found: $totalArtifacts" -Level "INFO"

if ($totalArtifacts -eq 0) {
    Write-CleanupLog "[+] SYSTEM CLEAN - No BYOVD artifacts detected" -Level "SUCCESS"
} else {
    Write-CleanupLog "[!] CLEANUP REQUIRED - $totalArtifacts artifacts found" -Level "WARNING"
    Write-CleanupLog "Review the report for detailed cleanup instructions" -Level "WARNING"
}

Write-CleanupLog "Report File: $reportPath" -Level "INFO"
Write-CleanupLog "Log File: $script:CleanupLog" -Level "INFO"