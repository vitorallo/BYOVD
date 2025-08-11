# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a threat intelligence documentation repository focused on a specific actor or cybercriminal group. It contains cybersecurity research documents, not executable code.

When editing or analyzing these documents, maintain the professional threat intelligence format and ensure accuracy of technical details and ATT&CK technique mappings.

## Repository Structure

The repository contains threat intelligence documentation in Markdown format:

- **Threat Profile**: `*Threat Profile.md` - Comprehensive threat analysis which includes detailed TTPs
- **Additional info**: `*.md` - Additional info on the threat profile
- **Case Study**: `*.md` - Search for a possible recent attack use case if not provided

## Content

Documents should provide the folloing intelligence:

1. **Threat Actor Profiling**: Actor's aliases, motivations, target selection
2. **Attack Methodology**: Social engineering, initial access and escalation info with clear outcome of the goals of the attack
3. **Technical Analysis**: Tool usage (RMM software, RATs, legitimate tools misused)
4. **Case Studies**: Real-world examples with focus on recent attacks
5. **Defensive Guidance**: Mitigations, detection methods, threat hunting approaches (generate them in case missing)

## Working with This Repository ***** IMPORTANT *****

- use always MITRE ATTACK mapping to classify TTPs
- enritch intelligence by consulting OpenCTI via MCP (if available) with:
    - additional TTPs or Attack Patterns
    - additional info or extract IoCs
    - behavioural indicators
- search the web if necessary
- produce always MD reports and TTPs listed in CSV with the necessary info
- produce threat hunting runbook and attack simulation plan
- write KQL code for microsoft sentinel when needed
- write yaml code using Atomic RedTeam testing for attack simulation (include commands, use of assembly .net executables, use of BOF, use of powershell scripts)
- do not add ttps to the existing ttp.db_csv, generate new csv files when needed 
- add logo at the beginning of the MD file with this: ![Crimson7](https://cdn.prod.website-files.com/67711bb097dfc839a8004a6c/68482a560217871b92242435_c7_logo_small.png)  

### TASKS
☒ Search web for additional threat intelligence if needed
☒ Search OpenCTI using MCP client
☒ Analyze existing threat documents and extract TTPs with MITRE ATT&CK mapping
☒ Create CSV database of TTPs for the threat actor
☒ Generate threat hunting runbook with KQL queries for Microsoft Sentinel
☒ Create attack simulation plan with tests

## Threat Hunting Runbook *** OUTPUT FORMATTER ***
Threat hunting runbook is produced with KQL code for Microsoft Sentinel.
follow this indications to produce the report:
- Structure of the document:
    1) Purpose
    2) Threat Context (includes actor or actors enumeration, motivation and KeyTTPs listing)
    3) Technical prerequisite for threat hunting
    4) Threat Hunting Hypotheses (includes mapping and enumeration to MITRE TTPs, Hypotesis explanation, Hunting Focus, KQL query/queries in a code section, Investigation steps over the query output)
    5) Summary of the runbook including a summary table with the enumerated hunts hypotesis and ttps described previously
    6) references section with simple and short hyperlinks if available and necessary
- close the document with "This document is prepared by Crimson7" add the year and any versioning information
- generate KQL code with the latest sintax and minding Microsoft MDE and Sentinel tables, the code should execute or in case add technology prerequisites (e.g. sysmon)
- FIRST consult opencti MCP for any possible IoC that could be included in hunting queries

## Attack Simulation Plan *** OUTPUT FORMATTER ***
This is a document that details how to simulate an attack using atomic simulations on the TTP described.
### subtasks
- first read and select TTPs tests from @ttp_db.csv and make sure to map them by name in the document, inclduing all the mitre related info
- if you spot additional tests needs that are not included the the file, generate a new 'additional_ttps.csv' and attempt generate code and write them in a subfolder 'yaml'
    1) code must be follow the atomic redteam convention (yaml test same below)
    2) you can consider to write attacks based on BOF, Powershell script, direct CMD or PS commands or use of any other tool you can scount on the web that can be compiled in .net assembly. The use of plain .exe file is possible. 
    3) identify the tools to use, describe the procedures to execute the TTP and relative links on repositories or source for an operator to download and compile the tools or mount the attack manually
- prepare the plan
sample of yaml:

'''
id: 2c79dc55-ea65-45c6-8bd3-699f3dee32a0
name: adfind_enumerate_active_directory_admins
description: |
  Adfind tool can be used for reconnaissance in an Active directory environment. This example has been documented by ransomware actors enumerating Active Directory Admin accounts
  reference- http://www.joeware.net/freetools/tools/adfind/, https://stealthbits.com/blog/fun-with-active-directorys-admincount-attribute/
technique:
  id: T1087.002
  name: 'Account Discovery: Domain Account'
tactic: discovery
metadata:
  authors:
    - RedCanary Atomic Red Team
  tags: 
    - privileges: user
    - sophistication: minimal
  payloads:
    AdFind.exe: 4f4f8cf0f9b47d0ad95d159201fe7e72fbc8448d
platforms:
  windows:
    cmd: *** can also be execute-assembly, powershell, bof, 
      command: AdFind.exe -sc admincountdmp
      payload: AdFind.exe
'''