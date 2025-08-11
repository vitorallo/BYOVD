![Crimson7](https://cdn.prod.website-files.com/67711bb097dfc839a8004a6c/68482a560217871b92242435_c7_logo_small.png)

# BYOVD (Bring Your Own Vulnerable Driver) Attack Simulation Plan

## Executive Summary

This document outlines comprehensive attack simulation scenarios for BYOVD (Bring Your Own Vulnerable Driver) techniques using Atomic Red Team testing framework. The simulations are designed to test defensive capabilities against kernel-level attacks that leverage vulnerable signed drivers to bypass security controls and achieve system compromise.

## TTPs Mapping from Database

Based on the BYOVD TTPs database (`byovd_ttps.csv`), the following high-priority techniques have been selected for simulation:

### Selected TTPs for Simulation:
- **TTP008** - T1068: Exploitation for Privilege Escalation (Vulnerable driver exploitation)
- **TTP010** - T1562.001: Impair Defenses - Disable or Modify Tools (Security process termination)
- **TTP014** - T1553.005: Driver Signature Enforcement Bypass
- **TTP015** - T1003.001: OS Credential Dumping - LSASS Memory access
- **TTP023** - T1562.002: Disable Windows Event Logging (ETW disruption)

## Attack Simulation Scenarios

### Scenario 1: Vulnerable Driver Installation and Exploitation

**Objective**: Simulate the installation and exploitation of a vulnerable driver for privilege escalation
**MITRE ATT&CK**: T1068 - Exploitation for Privilege Escalation
**Threat Actor Simulation**: SCATTERED SPIDER, Medusa Ransomware

#### Tools and Resources Required:
- **KDMapper**: Open-source tool for mapping non-signed drivers
- **Vulnerable Driver**: Intel Ethernet diagnostics driver (iqvw64.sys) or test vulnerable driver
- **PowerShell**: For installation scripts
- **Administrative Privileges**: Required for driver installation

#### Preparation Steps:
1. Download vulnerable driver samples from LOLDrivers project
2. Set up isolated test environment with endpoint monitoring
3. Prepare PowerShell scripts for driver installation
4. Configure monitoring for driver installation events

### Scenario 2: Security Process Termination via Kernel Access

**Objective**: Simulate malicious driver terminating security processes
**MITRE ATT&CK**: T1562.001 - Impair Defenses: Disable or Modify Tools
**Threat Actor Simulation**: Medusa (ABYSSWORKER), SCATTERED SPIDER

#### Tools and Resources Required:
- **Custom Driver**: Simulated malicious driver with process termination capabilities
- **Process Termination Tool**: PowerShell scripts to simulate process killing
- **Target Processes**: Mock security processes for safe testing

#### Preparation Steps:
1. Create mock security processes that can be safely terminated
2. Develop PowerShell scripts to simulate driver-based process termination
3. Set up process monitoring and alerting
4. Prepare incident response procedures

### Scenario 3: LSASS Memory Access for Credential Dumping

**Objective**: Simulate kernel-level credential dumping from LSASS
**MITRE ATT&CK**: T1003.001 - OS Credential Dumping: LSASS Memory
**Threat Actor Simulation**: Multiple APT groups using BYOVD

#### Tools and Resources Required:
- **Mimikatz**: For credential dumping simulation
- **PowerShell**: For process memory access
- **Kernel Access Simulation**: Scripts to simulate kernel-level memory access
- **Test Credentials**: Safe test accounts for extraction

#### Preparation Steps:
1. Set up test environment with safe credentials
2. Configure LSASS protection settings for testing
3. Prepare credential dumping tools
4. Set up memory access monitoring

### Scenario 4: Social Engineering for Fake Driver Updates

**Objective**: Simulate social engineering campaigns using fake driver updates to deliver BYOVD payloads
**MITRE ATT&CK**: T1566.002 - Phishing: Spearphishing Link, T1105 - Ingress Tool Transfer, T1059.001 - PowerShell, T1059.005 - Visual Basic
**Threat Actor Simulation**: Lazarus Group (ClickFake campaigns)

#### Tools and Resources Required:
- **curl/wget**: For file download simulation
- **PowerShell**: For archive extraction and execution
- **VBS Scripts**: For final payload execution simulation
- **Driver-themed payloads**: Test files with driver-related names
- **Fake domains**: Test infrastructure mimicking driver update sites

#### Preparation Steps:
1. Set up isolated web server with driver-themed content
2. Create test VBS scripts with safe payloads
3. Prepare monitoring for multi-stage execution chains
4. Configure network monitoring for suspicious downloads
5. Set up email security testing for driver update lures

## Atomic Red Team Test Definitions

### Test 1: Vulnerable Driver Loading Simulation

```yaml
attack_technique: T1068
display_name: BYOVD - Vulnerable Driver Loading
atomic_tests:
- name: Load Vulnerable Intel Ethernet Driver
  auto_generated_guid: 7c8b9c45-2d4e-4f8a-9b3c-1e7d9f2a5b8c
  description: |
    Simulates loading of vulnerable Intel Ethernet diagnostics driver (iqvw64.sys) 
    commonly used in BYOVD attacks by SCATTERED SPIDER and other threat actors.
    This test requires administrative privileges and should only be run in isolated environments.
  supported_platforms:
  - windows
  input_arguments:
    driver_path:
      description: Path to the vulnerable driver file
      type: string
      default: C:\Windows\System32\drivers\iqvw64.sys
    service_name:
      description: Name of the service to create for the driver
      type: string
      default: VulnEthDriver
  dependency_executor_name: powershell
  dependencies:
  - description: Vulnerable driver must exist on disk
    prereq_command: |
      Test-Path "#{driver_path}"
    get_prereq_command: |
      Write-Host "Please obtain vulnerable driver for testing from LOLDrivers project"
      Write-Host "WARNING: Only use in controlled test environment"
  executor:
    command: |
      # Create service for vulnerable driver
      sc.exe create #{service_name} binPath= "#{driver_path}" type= kernel start= demand
      
      # Start the vulnerable driver service
      sc.exe start #{service_name}
      
      # Verify driver loaded
      Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "#{service_name}"}
    cleanup_command: |
      # Stop and delete the service
      sc.exe stop #{service_name}
      sc.exe delete #{service_name}
    name: powershell
    elevation_required: true
```

### Test 2: Security Process Termination Simulation

```yaml
attack_technique: T1562.001
display_name: BYOVD - Security Process Termination
atomic_tests:
- name: Simulate Security Process Termination via Kernel Access
  auto_generated_guid: a1b2c3d4-e5f6-7890-1234-567890abcdef
  description: |
    Simulates the termination of security processes using elevated privileges
    mimicking malicious driver behavior observed in Medusa ransomware attacks.
  supported_platforms:
  - windows
  input_arguments:
    target_processes:
      description: Comma-separated list of process names to target
      type: string
      default: notepad.exe,calc.exe,mspaint.exe
  dependency_executor_name: powershell
  dependencies:
  - description: Target processes should be running for realistic simulation
    prereq_command: |
      $processes = "#{target_processes}".Split(',')
      foreach ($proc in $processes) {
        if (-not (Get-Process -Name $proc.Replace('.exe','') -ErrorAction SilentlyContinue)) {
          Start-Process $proc
          Start-Sleep 2
        }
      }
  executor:
    command: |
      # Simulate malicious driver process termination
      $processes = "#{target_processes}".Split(',')
      Write-Host "Simulating kernel-level process termination..."
      
      foreach ($processName in $processes) {
        $procName = $processName.Replace('.exe','')
        $targetProc = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($targetProc) {
          Write-Host "Terminating process: $processName (PID: $($targetProc.Id))"
          Stop-Process -Id $targetProc.Id -Force
          Write-Host "Process terminated successfully"
        }
      }
      
      # Log the termination event
      Write-EventLog -LogName Application -Source "BYOVD-Test" -EventId 1001 -EntryType Warning -Message "Simulated security process termination via BYOVD"
    cleanup_command: |
      Write-Host "Test completed - processes terminated as part of simulation"
    name: powershell
    elevation_required: true
```

### Test 3: Driver Signature Enforcement Bypass

```yaml
attack_technique: T1553.005
display_name: BYOVD - Driver Signature Enforcement Bypass
atomic_tests:
- name: Simulate DSE Bypass via Registry Modification
  auto_generated_guid: f1e2d3c4-b5a6-9870-4321-098765fedcba
  description: |
    Simulates bypassing Windows Driver Signature Enforcement by modifying registry values
    commonly used in BYOVD attacks to load unsigned malicious drivers.
  supported_platforms:
  - windows
  input_arguments:
    backup_dse_settings:
      description: Whether to backup current DSE settings
      type: boolean
      default: true
  dependency_executor_name: powershell
  dependencies:
  - description: Registry backup location should be accessible
    prereq_command: |
      Test-Path "C:\temp" -ErrorAction SilentlyContinue
    get_prereq_command: |
      New-Item -Path "C:\temp" -ItemType Directory -Force
  executor:
    command: |
      # Backup current settings if requested
      if ("#{backup_dse_settings}" -eq "true") {
        Write-Host "Backing up current DSE registry settings..."
        $backupPath = "C:\temp\dse_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\CI" $backupPath
        Write-Host "Backup saved to: $backupPath"
      }
      
      # Simulate DSE bypass (modify test registry values)
      Write-Host "Simulating Driver Signature Enforcement bypass..."
      
      # Create test registry key for simulation
      $testPath = "HKLM:\SOFTWARE\BYOVD-Test\CI-Simulation"
      New-Item -Path $testPath -Force | Out-Null
      
      # Simulate registry modifications that would bypass DSE
      Set-ItemProperty -Path $testPath -Name "TestSigning" -Value 1 -Type DWord
      Set-ItemProperty -Path $testPath -Name "VulnerableDriverBlocklistEnable" -Value 0 -Type DWord
      Set-ItemProperty -Path $testPath -Name "RequireDriverSignatureEnforcement" -Value 0 -Type DWord
      
      Write-Host "Simulated DSE bypass registry modifications completed"
      Write-Host "NOTE: This is a simulation - actual DSE was not modified"
    cleanup_command: |
      # Remove test registry key
      Remove-Item -Path "HKLM:\SOFTWARE\BYOVD-Test" -Recurse -Force -ErrorAction SilentlyContinue
      Write-Host "Test registry entries cleaned up"
    name: powershell
    elevation_required: true
```

### Test 4: LSASS Memory Access Simulation

```yaml
attack_technique: T1003.001
display_name: BYOVD - LSASS Memory Access
atomic_tests:
- name: Simulate Kernel-Level LSASS Memory Access
  auto_generated_guid: 9a8b7c6d-5e4f-3210-9876-543210abcdef
  description: |
    Simulates accessing LSASS process memory using elevated privileges
    mimicking kernel-level credential dumping via malicious drivers.
  supported_platforms:
  - windows
  input_arguments:
    simulation_only:
      description: Run in simulation mode without actual memory access
      type: boolean
      default: true
  dependency_executor_name: powershell
  dependencies:
  - description: LSASS process should be running
    prereq_command: |
      Get-Process -Name lsass -ErrorAction SilentlyContinue
  executor:
    command: |
      if ("#{simulation_only}" -eq "true") {
        Write-Host "Running in SIMULATION MODE - no actual memory access performed"
        
        # Simulate the process identification phase
        $lsassProc = Get-Process -Name lsass
        Write-Host "Target LSASS Process identified: PID $($lsassProc.Id)"
        
        # Simulate memory access attempt (without actual access)
        Write-Host "Simulating kernel-level memory access to LSASS..."
        Write-Host "In real attack: Bypassing LSA protection using kernel privileges"
        Write-Host "In real attack: Reading authentication packages and credentials"
        
        # Log the simulation event
        Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EventId 4656 -EntryType Information -Message "BYOVD Test: Simulated LSASS memory access"
        
        Write-Host "Simulation completed - no actual credential extraction performed"
      } else {
        Write-Host "ERROR: Actual memory access disabled for safety"
        Write-Host "This test only runs in simulation mode"
      }
    cleanup_command: |
      Write-Host "LSASS memory access simulation completed"
    name: powershell
    elevation_required: true
```

### Test 5: ETW Disruption Simulation

```yaml
attack_technique: T1562.002
display_name: BYOVD - ETW Disruption
atomic_tests:
- name: Simulate ETW Provider Disruption
  auto_generated_guid: 8f7e6d5c-4b3a-2109-8765-432109876543
  description: |
    Simulates disrupting Event Tracing for Windows (ETW) providers
    commonly performed by malicious drivers to evade detection.
  supported_platforms:
  - windows
  input_arguments:
    target_provider:
      description: ETW provider to target for disruption simulation
      type: string
      default: Microsoft-Windows-Threat-Intelligence
  dependency_executor_name: powershell
  dependencies:
  - description: ETW provider should be available
    prereq_command: |
      Get-EtwTraceProvider -Name "#{target_provider}" -ErrorAction SilentlyContinue
  executor:
    command: |
      Write-Host "Simulating ETW provider disruption..."
      
      # List current ETW sessions (reconnaissance phase)
      Write-Host "Enumerating active ETW sessions:"
      $sessions = logman query -ets
      Write-Host $sessions
      
      # Simulate provider disruption (without actual disruption)
      Write-Host "Simulating disruption of ETW provider: #{target_provider}"
      Write-Host "In real attack: Kernel-level callback removal would occur here"
      Write-Host "In real attack: ETW events would be blocked from reaching consumers"
      
      # Create test event to verify ETW functionality
      Write-EventLog -LogName Application -Source "BYOVD-Test" -EventId 1002 -EntryType Information -Message "ETW disruption simulation test event"
      
      Write-Host "ETW disruption simulation completed"
    cleanup_command: |
      Write-Host "ETW disruption test completed - no actual disruption performed"
    name: powershell
    elevation_required: true
```

## Attack Simulation Execution Plan

### Phase 1: Environment Preparation
1. **Test Environment Setup**
   - Isolated Windows 10/11 virtual machines
   - Endpoint monitoring agents (Windows Defender, Sysmon)
   - Network monitoring capabilities
   - Backup and restore capabilities

2. **Tool Preparation**
   - Download Atomic Red Team framework
   - Prepare vulnerable driver samples (test environment only)
   - Set up monitoring dashboards
   - Configure alert thresholds

### Phase 2: Simulation Execution
1. **Execute Test 1**: Vulnerable Driver Loading
   - Monitor for driver installation events
   - Validate detection capabilities
   - Document bypass techniques observed

2. **Execute Test 2**: Security Process Termination
   - Monitor process termination patterns
   - Test incident response procedures
   - Evaluate alert generation

3. **Execute Test 3**: DSE Bypass Simulation
   - Monitor registry modifications
   - Test policy enforcement
   - Validate configuration management

4. **Execute Test 4**: LSASS Access Simulation
   - Monitor privileged process access
   - Test credential protection mechanisms
   - Validate memory protection features

5. **Execute Test 5**: ETW Disruption
   - Monitor event logging integrity
   - Test logging redundancy
   - Validate monitoring coverage

### Phase 3: Analysis and Reporting
1. **Detection Analysis**
   - Evaluate detection coverage for each TTP
   - Identify detection gaps
   - Document false positives/negatives

2. **Response Evaluation**
   - Assess incident response effectiveness
   - Test containment procedures
   - Validate forensic data collection

3. **Improvement Recommendations**
   - Enhance detection rules
   - Update response procedures
   - Implement additional controls

## Operator Manual

### Prerequisites for Operators
1. **Technical Skills**
   - Windows kernel architecture understanding
   - PowerShell scripting capabilities
   - Registry modification experience
   - Process monitoring knowledge

2. **Tools and Access**
   - Administrative privileges on test systems
   - Atomic Red Team framework installation
   - Vulnerable driver samples (test-safe versions)
   - Monitoring and logging tools

### Safety Considerations
- **Isolated Environment**: Always run in isolated test environment
- **No Production Systems**: Never execute on production infrastructure
- **Backup Systems**: Maintain system restore points
- **Monitoring**: Ensure comprehensive logging and monitoring
- **Documentation**: Record all activities for analysis

### Compilation and Tool Sources

#### Vulnerable Drivers (Test Environment Only)
- **LOLDrivers Project**: https://github.com/magicsword-io/LOLDrivers
- **Microsoft Vulnerable Driver Blocklist**: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
- **Test Driver Samples**: Use only in controlled environments

#### Tool Compilation Instructions
1. **KDMapper**: Compile from https://github.com/TheCruZ/kdmapper
2. **Custom Test Drivers**: Develop minimal drivers for safe testing
3. **PowerShell Modules**: Use built-in Windows capabilities

#### Repository Sources
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Windows Driver Kit**: https://docs.microsoft.com/en-us/windows-hardware/drivers/

---

**IMPORTANT SECURITY NOTICE**: This attack simulation plan is designed for authorized security testing and research purposes only. All tests should be conducted in isolated environments with proper authorization. Misuse of these techniques against unauthorized systems is illegal and unethical.

---

This document is prepared by Crimson7 - 2025 Version 1.0