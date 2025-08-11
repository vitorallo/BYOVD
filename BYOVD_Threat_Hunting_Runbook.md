![Crimson7](https://cdn.prod.website-files.com/67711bb097dfc839a8004a6c/68482a560217871b92242435_c7_logo_small.png)

# BYOVD (Bring Your Own Vulnerable Driver) Threat Hunting Runbook

## 1. Purpose

This runbook provides comprehensive threat hunting methodologies and KQL queries for detecting Bring Your Own Vulnerable Driver (BYOVD) attacks within Microsoft Sentinel environments. The runbook focuses on behavioral indicators, kernel-level activities, and process anomalies associated with malicious driver exploitation techniques commonly used by threat actors including SCATTERED SPIDER, Medusa ransomware, and other advanced persistent threats.

## 2. Threat Context

### Actor Enumeration
- **SCATTERED SPIDER (UNC3944, Octo Tempest, Storm-0875)**: Advanced cybercriminal group targeting telecommunications, BPO, MSSP, and financial services
- **Medusa Ransomware**: Ransomware-as-a-Service operation utilizing ABYSSWORKER driver for EDR evasion
- **Kasseika Ransomware**: Leverages viragt64.sys driver to terminate 991+ security processes
- **Various APT Groups**: Including Lazarus Group (first recorded BYOVD abuse in 2021)

### Motivation
- **Ransomware Deployment**: Disabling security controls for successful encryption operations
- **EDR Evasion**: Bypassing endpoint detection and response solutions
- **Persistence**: Establishing kernel-level persistence mechanisms
- **Credential Theft**: Accessing protected memory spaces for credential dumping

### Key TTPs
- **T1068**: Exploitation for Privilege Escalation (Vulnerable driver exploitation)
- **T1562.001**: Impair Defenses - Disable or Modify Tools (Security process termination)
- **T1014**: Rootkit (Kernel-level hiding capabilities)
- **T1553.005**: Subvert Trust Controls - Driver Signature Enforcement Bypass
- **T1003.001**: OS Credential Dumping - LSASS Memory access

## 3. Technical Prerequisites for Threat Hunting

### Required Data Sources
- **Microsoft Defender for Endpoint (MDE)**: DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents
- **Sysmon**: Process creation, file creation, registry modifications (EventIDs 1, 11, 13)
- **Windows Security Events**: Service installations (EventID 7045), logon events
- **Microsoft Sentinel**: SecurityEvent, DeviceEvents tables

### Required Technologies
- Microsoft Sentinel workspace with MDE connector
- Sysmon deployment for enhanced process monitoring
- Windows Event Logging enabled on critical systems
- Advanced hunting capabilities in Microsoft 365 Defender

## 4. Threat Hunting Hypotheses

### Hunt 1: Vulnerable Driver Installation Detection

**MITRE ATT&CK Mapping**: T1068 (Exploitation for Privilege Escalation), T1547.006 (Kernel Modules and Extensions)

**Hypothesis Explanation**: Threat actors install known vulnerable drivers to exploit kernel-level vulnerabilities for privilege escalation and security bypass.

**Hunting Focus**: Detection of known vulnerable driver installations including Intel Ethernet diagnostics driver (iqvw64.sys), Dell drivers (dbutil_2_3.sys), and other LOLDrivers.

**KQL Query**:
```kql
// Hunt for known vulnerable driver installations
let VulnerableDrivers = pack_array(
    "iqvw64.sys",        // Intel Ethernet diagnostics driver - CVE-2015-2291
    "dbutil_2_3.sys",    // Dell driver - CVE-2021-21551
    "dbutildrv2.sys",    // Dell driver variants
    "asrdrv101.sys",     // ASRock driver
    "ucorew64.sys",      // UCore driver
    "atillk64.sys",      // ATI driver - CVE-2019-7246
    "gdrv.sys",          // Gigabyte driver
    "smuol.sys",         // ABYSSWORKER (Medusa)
    "viragt64.sys"       // VirIT Antivirus driver
);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (VulnerableDrivers)
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine contains "sc " and ProcessCommandLine contains "create"
    | project ServiceCreationTime=Timestamp, DeviceName, ServiceCommandLine=ProcessCommandLine
) on DeviceName
| where abs(datetime_diff('minute', Timestamp, ServiceCreationTime)) < 5
| extend ThreatScore = case(
    FileName =~ "smuol.sys", 10,
    FileName =~ "iqvw64.sys", 9,
    FileName =~ "viragt64.sys", 9,
    FileName contains "dbutil", 8,
    7
)
| order by ThreatScore desc, Timestamp desc
```

**Investigation Steps**:
1. Validate driver legitimacy through VirusTotal and Microsoft threat intelligence
2. Check for associated service creation events within 5-minute window
3. Analyze parent process and command line arguments for installation context
4. Review network connections and file modifications around installation time
5. Check for subsequent security process terminations

### Hunt 2: Security Process Termination via Kernel Access

**MITRE ATT&CK Mapping**: T1562.001 (Impair Defenses - Disable or Modify Tools)

**Hypothesis Explanation**: Malicious drivers terminate security processes to evade detection and prevent incident response.

**Hunting Focus**: Unusual process termination patterns targeting security products, especially when preceded by driver installations.

**KQL Query**:
```kql
// Hunt for security process terminations potentially via malicious drivers
let SecurityProcesses = pack_array(
    "MsMpEng.exe",          // Windows Defender
    "CSAgent.exe",          // CrowdStrike Falcon
    "XDRAgent.exe",         // Palo Alto Cortex XDR
    "SentinelAgent.exe",    // SentinelOne
    "cyserver.exe",         // Cylance
    "cb.exe",               // Carbon Black
    "TaniumClient.exe",     // Tanium
    "HealthService.exe",    // SCOM/SCCM
    "LogonTracer.exe"       // Various logging tools
);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessTerminated"
| where ProcessFileName in~ (SecurityProcesses)
| summarize TerminatedCount = count(), 
            ProcessList = make_set(ProcessFileName),
            FirstTermination = min(Timestamp),
            LastTermination = max(Timestamp)
            by DeviceName, bin(Timestamp, 1h)
| where TerminatedCount >= 3  // Multiple security processes terminated
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName endswith ".sys"
    | where ActionType == "FileCreated"
    | project DriverInstallTime=Timestamp, DeviceName, DriverName=FileName, DriverPath=FolderPath
) on DeviceName
| where abs(datetime_diff('hour', FirstTermination, DriverInstallTime)) <= 24
| project DeviceName, FirstTermination, LastTermination, TerminatedCount, ProcessList, DriverName, DriverPath, DriverInstallTime
| extend ThreatLevel = case(
    TerminatedCount >= 5, "High",
    TerminatedCount >= 3, "Medium",
    "Low"
)
| order by TerminatedCount desc
```

**Investigation Steps**:
1. Correlate process terminations with recent driver installations on same host
2. Check if terminated processes were critical security services
3. Analyze process termination method (normal shutdown vs forceful kill)
4. Review system logs for service restart attempts and failures
5. Examine memory dumps if available for rootkit indicators

### Hunt 3: Kernel-Level LSASS Access for Credential Dumping

**MITRE ATT&CK Mapping**: T1003.001 (OS Credential Dumping - LSASS Memory)

**Hypothesis Explanation**: Attackers leverage kernel access to bypass LSA protection and dump credentials from LSASS memory.

**Hunting Focus**: Unusual LSASS access patterns potentially facilitated by malicious drivers.

**KQL Query**:
```kql
// Hunt for potential LSASS credential dumping via kernel access
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessFileName =~ "lsass.exe"
| where ActionType in ("ProcessAccessed", "ProcessHandleCreated")
| where InitiatingProcessFileName !in~ ("services.exe", "winlogon.exe", "csrss.exe", "wininit.exe")
| summarize AccessCount = count(),
            AccessingProcesses = make_set(InitiatingProcessFileName),
            FirstAccess = min(Timestamp),
            LastAccess = max(Timestamp)
            by DeviceName, bin(Timestamp, 10m)
| where AccessCount >= 3
| join kind=leftouter (
    // Look for suspicious driver activity around the same time
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName endswith ".sys"
    | where ActionType in ("FileCreated", "FileModified")
    | project DriverActivity=Timestamp, DeviceName, SuspiciousDriver=FileName
) on DeviceName
| where abs(datetime_diff('minute', FirstAccess, DriverActivity)) <= 30
| join kind=leftouter (
    // Check for credential dumping tools
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine contains_any ("mimikatz", "procdump", "comsvcs.dll", "rundll32")
    | project CredToolTime=Timestamp, DeviceName, CredTool=ProcessFileName, CredToolCmd=ProcessCommandLine
) on DeviceName
| where abs(datetime_diff('minute', FirstAccess, CredToolTime)) <= 15
| project DeviceName, FirstAccess, LastAccess, AccessCount, AccessingProcesses, SuspiciousDriver, CredTool, CredToolCmd
| extend RiskLevel = case(
    isnotempty(SuspiciousDriver) and isnotempty(CredTool), "Critical",
    isnotempty(SuspiciousDriver) or isnotempty(CredTool), "High",
    AccessCount >= 5, "Medium",
    "Low"
)
| order by RiskLevel desc, AccessCount desc
```

**Investigation Steps**:
1. Validate LSASS access legitimacy by checking accessing process reputation
2. Correlate with recent driver installations and security tool terminations
3. Check for credential dumping tool execution within correlation window
4. Review authentication logs for suspicious logon patterns post-access
5. Analyze memory forensics for credential extraction artifacts

### Hunt 4: Driver Signature Enforcement Bypass Detection

**MITRE ATT&CK Mapping**: T1553.005 (Subvert Trust Controls - Driver Signature Enforcement Bypass)

**Hypothesis Explanation**: Attackers disable or bypass Windows Driver Signature Enforcement to load unsigned malicious drivers.

**Hunting Focus**: Registry modifications and policy changes related to DSE bypass, Test Signing mode activation.

**KQL Query**:
```kql
// Hunt for Driver Signature Enforcement bypass attempts
let DSERegistryKeys = pack_array(
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\PolicyState", 
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\TestSigning"
);
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any (DSERegistryKeys)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| extend DSEBypassIndicator = case(
    RegistryValueName =~ "VulnerableDriverBlocklistEnable" and RegistryValueData =~ "0", "Blocklist Disabled",
    RegistryValueName =~ "TestSigning" and RegistryValueData =~ "1", "Test Signing Enabled",
    RegistryValueName =~ "IntegrityChecks" and RegistryValueData =~ "0", "Integrity Checks Disabled",
    RegistryValueName =~ "RequireDriverSignatureEnforcement" and RegistryValueData =~ "0", "DSE Disabled",
    "Other DSE Modification"
)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, 
          DSEBypassIndicator, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    // Look for bcdedit commands that might enable test signing
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine contains "bcdedit"
    | where ProcessCommandLine contains_any ("testsigning", "nointegritychecks", "loadoptions")
    | project BCDEditTime=Timestamp, DeviceName, BCDCommand=ProcessCommandLine
) on DeviceName
| where abs(datetime_diff('hour', Timestamp, BCDEditTime)) <= 2
| extend ThreatScore = case(
    DSEBypassIndicator == "Test Signing Enabled", 9,
    DSEBypassIndicator == "DSE Disabled", 10,
    DSEBypassIndicator == "Blocklist Disabled", 8,
    5
)
| order by ThreatScore desc, Timestamp desc
```

**Investigation Steps**:
1. Verify if DSE bypass was performed by legitimate administrative processes
2. Check for subsequent unsigned driver loading attempts
3. Correlate with bcdedit command execution for test signing enablement
4. Review system reboot events following registry modifications
5. Examine driver installation events post-DSE bypass

### Hunt 5: Rootkit Behavior Detection via Process Hiding

**MITRE ATT&CK Mapping**: T1014 (Rootkit)

**Hypothesis Explanation**: Malicious drivers implement rootkit functionality to hide processes, files, and network connections from security tools.

**Hunting Focus**: Process enumeration discrepancies between different data sources, indicating potential process hiding.

**KQL Query**:
```kql
// Hunt for potential rootkit behavior through process enumeration discrepancies
// Compare process lists from different sources to identify hidden processes
let SysmonProcesses = (
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 1  // Sysmon Process Creation
    | extend ProcessGuid = tostring(EventData.ProcessGuid)
    | project TimeGenerated, Computer, ProcessGuid, ProcessName=tostring(EventData.Image), 
              ParentProcessName=tostring(EventData.ParentImage)
    | summarize SysmonProcessCount = dcount(ProcessGuid) by Computer, bin(TimeGenerated, 5m)
);
let MDEProcesses = (
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where ActionType == "ProcessCreated"
    | project Timestamp, DeviceName, ProcessId, ProcessFileName, ParentProcessFileName
    | summarize MDEProcessCount = dcount(ProcessId) by DeviceName, bin(Timestamp, 5m)
);
SysmonProcesses
| join kind=leftouter (MDEProcesses) on $left.Computer == $right.DeviceName and $left.TimeGenerated == $right.Timestamp
| where isnotempty(MDEProcessCount) and isnotempty(SysmonProcessCount)
| extend ProcessCountDifference = abs(SysmonProcessCount - MDEProcessCount)
| extend DiscrepancyPercentage = todouble(ProcessCountDifference) / todouble(max_of(SysmonProcessCount, MDEProcessCount)) * 100
| where DiscrepancyPercentage > 20  // Significant discrepancy threshold
| join kind=leftouter (
    // Look for suspicious driver activity
    DeviceFileEvents
    | where Timestamp > ago(1d)
    | where FileName endswith ".sys"
    | where ActionType == "FileCreated"
    | project DriverTime=Timestamp, DeviceName, SuspiciousDriver=FileName
) on $left.Computer == $right.DeviceName
| where abs(datetime_diff('hour', TimeGenerated, DriverTime)) <= 6
| project Computer, TimeGenerated, SysmonProcessCount, MDEProcessCount, 
          DiscrepancyPercentage, SuspiciousDriver
| extend RiskLevel = case(
    DiscrepancyPercentage > 50, "Critical",
    DiscrepancyPercentage > 30, "High", 
    "Medium"
)
| order by DiscrepancyPercentage desc
```

**Investigation Steps**:
1. Manually enumerate processes using multiple tools (tasklist, wmic, PowerShell)
2. Compare results with different EDR agent reports
3. Check for kernel-level hooks or callback removals in memory
4. Analyze system performance metrics for hidden resource consumption
5. Perform memory forensics to identify hidden processes

### Hunt 6: Fake Driver Update Social Engineering Detection

**MITRE ATT&CK Mapping**: T1566.002 (Phishing: Spearphishing Link), T1105 (Ingress Tool Transfer), T1059.001 (PowerShell), T1059.005 (Visual Basic)

**Hypothesis Explanation**: Threat actors use social engineering with fake driver update campaigns to deliver malicious payloads that could include BYOVD components, leveraging driver-themed domains and filenames to appear legitimate.

**Hunting Focus**: Detection of multi-stage command chains involving curl downloads, PowerShell archive extraction, and VBS execution with driver-themed filenames, as observed in Lazarus Group ClickFake campaigns.

**KQL Query**:
```kql
// Hunt for fake driver update social engineering campaigns
// Based on Lazarus Group ClickFake campaign observed command pattern
let DriverKeywords = pack_array(
    "nvidia", "nvidiadrivers", "driver", "driverfix", "driverupdate", 
    "amd", "intel", "graphics", "display", "audio", "ethernet"
);
let SuspiciousDomains = pack_array(
    "smartdriverfix", "driverupdate", "driverfix", "driverpatch", 
    "nvidiaupdate", "amdupdate", "intelupdate", "graphicsupdate"
);
// Step 1: Detect curl/wget downloads with driver-themed content
let DriverDownloads = (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessFileName in~ ("curl.exe", "wget.exe", "powershell.exe", "cmd.exe")
    | where ProcessCommandLine has_any (DriverKeywords)
    | where ProcessCommandLine contains_any (".zip", ".exe", ".update")
    | where ProcessCommandLine has_any (SuspiciousDomains) or ProcessCommandLine contains "TEMP"
    | extend DownloadTime = Timestamp, DownloadCommand = ProcessCommandLine
    | project DownloadTime, DeviceName, DownloadCommand, InitiatingProcessFileName
);
// Step 2: Detect PowerShell archive extraction
let PowerShellExtraction = (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessFileName =~ "powershell.exe"
    | where ProcessCommandLine contains "Expand-Archive"
    | where ProcessCommandLine has_any (DriverKeywords)
    | extend ExtractionTime = Timestamp, ExtractionCommand = ProcessCommandLine
    | project ExtractionTime, DeviceName, ExtractionCommand
);
// Step 3: Detect VBS/WSF script execution
let VBSExecution = (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessFileName in~ ("wscript.exe", "cscript.exe")
    | where ProcessCommandLine contains "TEMP" 
    | where ProcessCommandLine has_any (DriverKeywords) or ProcessCommandLine contains_any (".vbs", ".wsf")
    | extend VBSTime = Timestamp, VBSCommand = ProcessCommandLine
    | project VBSTime, DeviceName, VBSCommand
);
// Correlate all three stages within time window
DriverDownloads
| join kind=leftouter (PowerShellExtraction) on DeviceName
| where abs(datetime_diff('minute', DownloadTime, ExtractionTime)) <= 10
| join kind=leftouter (VBSExecution) on DeviceName  
| where abs(datetime_diff('minute', ExtractionTime, VBSTime)) <= 5
| extend ThreatScore = case(
    isnotempty(VBSCommand) and isnotempty(ExtractionCommand), 10,
    isnotempty(ExtractionCommand), 8,
    6
)
| extend AttackChain = strcat(
    "Download: ", substring(DownloadCommand, 0, 100), " | ",
    "Extract: ", substring(ExtractionCommand, 0, 100), " | ", 
    "Execute: ", substring(VBSCommand, 0, 100)
)
// Additional correlation with file creation events
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName has_any (DriverKeywords)
    | where FileName endswith_any (".zip", ".vbs", ".exe")
    | where FolderPath contains "Temp"
    | summarize FileCount = count(), FileNames = make_set(FileName) by DeviceName
) on DeviceName
| project DeviceName, DownloadTime, ThreatScore, AttackChain, FileCount, FileNames
| where ThreatScore >= 8
| order by ThreatScore desc, DownloadTime desc
```

**Investigation Steps**:
1. Validate the legitimacy of downloaded files through reputation analysis
2. Check domain registration details and hosting infrastructure
3. Analyze the VBS script content for malicious behavior indicators
4. Review network traffic for additional C2 communications
5. Check for subsequent driver installation attempts or privilege escalation
6. Correlate with threat intelligence on known fake driver update campaigns

## 5. Summary of Runbook

### Hunt Summary Table

| Hunt ID | Hypothesis | Primary TTPs | Risk Level | Detection Confidence |
|---------|------------|--------------|------------|---------------------|
| Hunt 1 | Vulnerable Driver Installation | T1068, T1547.006 | High | High |
| Hunt 2 | Security Process Termination | T1562.001 | Critical | High |
| Hunt 3 | Kernel-Level LSASS Access | T1003.001 | Critical | Medium |
| Hunt 4 | DSE Bypass Detection | T1553.005 | High | Medium |
| Hunt 5 | Rootkit Behavior Detection | T1014 | Medium | Low |
| Hunt 6 | Fake Driver Update Social Engineering | T1566.002, T1105, T1059.001, T1059.005 | High | High |

### Key Indicators Summary
- **Known vulnerable driver installations** (iqvw64.sys, smuol.sys, viragt64.sys)
- **Mass security process terminations** (>3 security tools in 1-hour window)
- **Unusual LSASS memory access** patterns concurrent with driver activity
- **Registry modifications** disabling driver signature enforcement
- **Process enumeration discrepancies** between monitoring tools
- **Fake driver update campaigns** (curl + PowerShell + VBS execution chains)
- **Driver-themed social engineering** (smartdriverfix[.]cloud, nvidiadrivers.zip patterns)

### Recommended Actions
1. **Immediate Response**: Isolate systems showing high-confidence indicators
2. **Investigation Priority**: Focus on Critical and High-risk level detections
3. **Preventive Measures**: Implement Microsoft's vulnerable driver blocklist
4. **Monitoring Enhancement**: Deploy additional Sysmon configurations for kernel monitoring
5. **Threat Intelligence**: Continuously update IOC lists with latest vulnerable drivers

## 6. References

- https://attack.mitre.org/techniques/T1068/
- https://docs.microsoft.com/en-us/windows/security/threat-protection/
- https://www.loldrivers.io/
- https://github.com/magicsword-io/LOLDrivers
- https://blog.sekoia.io/clickfake-interview-campaign-by-lazarus/

---

This document is prepared by Crimson7 - 2025 Version 1.0