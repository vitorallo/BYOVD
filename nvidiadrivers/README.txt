NVIDIA Driver Update Package v496.13
=====================================

IMPORTANT: This is a BYOVD (Bring Your Own Vulnerable Driver) attack simulation package
created for cybersecurity research and testing purposes only.

Package Contents:
- iqvw64.sys          Mock vulnerable Intel Ethernet diagnostics driver
- install.vbs         Main installation script (VBS)
- setup.ps1           PowerShell installation component
- driver_loader.vbs   Direct driver loading script
- update.vbs          Complete attack chain simulation
- powershell_helper.ps1  PowerShell helper functions
- config.ini          Package configuration
- README.txt          This file

Attack Chain Simulation:
1. User receives fake driver update notification
2. Downloads nvidiadrivers.zip package
3. Executes: curl -> PowerShell -> VBS chain
4. VBS scripts load vulnerable driver
5. Driver exploitation provides kernel access
6. Post-exploitation activities commence

Installation Instructions:
==========================

AUTOMATIC INSTALLATION (Simulates real attack):
1. Extract package to temporary directory
2. Run: wscript.exe install.vbs
3. Follow installation prompts
4. Review generated logs and artifacts

MANUAL INSTALLATION (Component testing):
1. Execute individual scripts for testing:
   - wscript.exe driver_loader.vbs    (Driver loading only)
   - powershell.exe -File setup.ps1   (PowerShell components)
   - wscript.exe update.vbs           (Full attack simulation)

COMMAND LINE SIMULATION (Lazarus ClickFake):
1. Simulate the complete attack chain:
   curl -k -o "%TEMP%\nvidiadrivers.zip" [LOCAL_PATH]
   powershell -Command "Expand-Archive -Force -Path '%TEMP%\nvidiadrivers.zip' -DestinationPath '%TEMP%\nvidiadrivers'"
   wscript "%TEMP%\nvidiadrivers\install.vbs"

Security Considerations:
========================

THIS IS A SIMULATION PACKAGE - NOT REAL MALWARE:
- Contains mock vulnerable drivers (harmless)
- Simulates attack techniques without actual exploitation
- Creates test artifacts for detection validation
- All operations are logged for analysis

DETECTION OPPORTUNITIES:
- File creation in %TEMP%\nvidiadrivers\
- VBS script execution (wscript.exe)
- PowerShell execution with driver parameters
- Service creation attempts (kernel drivers)
- Registry modifications in NVIDIA paths
- Network downloads of driver packages

MITRE ATT&CK Techniques Demonstrated:
=====================================
T1566.002  Phishing: Spearphishing Link
T1105      Ingress Tool Transfer
T1059.001  Command and Scripting Interpreter: PowerShell
T1059.005  Command and Scripting Interpreter: Visual Basic
T1068      Exploitation for Privilege Escalation
T1562.001  Impair Defenses: Disable or Modify Tools
T1547.006  Boot or Logon Autostart Execution: Kernel Modules
T1014      Rootkit
T1553.005  Subvert Trust Controls: Driver Signature Enforcement Bypass
T1003.001  OS Credential Dumping: LSASS Memory
T1070.004  Indicator Removal on Host: File Deletion

Threat Actor Simulation:
========================
Primary: Lazarus Group (ClickFake campaign)
Secondary: SCATTERED SPIDER (UNC3944)
Tertiary: Medusa Ransomware operators

Real-world CVEs Simulated:
==========================
CVE-2015-2291  Intel Ethernet Diagnostics Driver (iqvw64.sys)
               Write-what-where vulnerability allowing arbitrary kernel writes

Clean Up Instructions:
=====================

AUTOMATIC CLEANUP:
- Run: powershell.exe -File "%TEMP%\BYOVD\tools\cleanup_verifier.ps1" -RemoveFoundArtifacts

MANUAL CLEANUP:
1. Delete %TEMP%\nvidiadrivers\ directory
2. Remove registry entries under HKCU\Software\BYOVD*
3. Clear application event logs with source "BYOVD-Test"
4. Delete any remaining *.log files in %TEMP%
5. Remove any test services created during simulation

Log Files Generated:
===================
- %TEMP%\nvidia_install_*.log      Main installation log
- %TEMP%\nvidia_powershell_*.log   PowerShell component log
- %TEMP%\vbs_driver_test.log       VBS execution log
- %TEMP%\byovd_*.log               Various simulation logs
- %TEMP%\nvidia_installation_summary.txt  Installation summary
- %TEMP%\nvidia_byovd_iocs.txt     IOCs for blue team

Support and Documentation:
==========================
- Full threat hunting runbook: BYOVD_Threat_Hunting_Runbook.md
- Attack simulation plan: BYOVD_Attack_Simulation_Plan.md
- TTP database: byovd_ttps.csv
- Additional atomic tests: yaml/ directory

WARNING: FOR AUTHORIZED SECURITY TESTING ONLY
==============================================
This package is designed for:
- Security research and education
- Red team exercises and training
- Blue team detection validation
- Incident response training
- Threat hunting exercises

DO NOT USE ON PRODUCTION SYSTEMS WITHOUT PROPER AUTHORIZATION
DO NOT USE FOR MALICIOUS PURPOSES

Created by: Crimson7 Threat Intelligence Team
Version: 1.0
Date: July 2025
Contact: research@crimson7.com

Legal Notice:
=============
This software is provided for educational and research purposes only.
Users are responsible for compliance with all applicable laws and regulations.
The authors assume no liability for misuse of this software.

By using this package, you acknowledge that you have proper authorization
for security testing on the target systems and agree to use it responsibly.