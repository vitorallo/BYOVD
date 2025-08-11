# Create Mock Vulnerable Driver - PowerShell Script
# Generates a realistic-looking driver file for BYOVD testing
# Author: Crimson7 Threat Intelligence Team

param(
    [string]$OutputPath = ".\test_vulnerable_driver.sys",
    [string]$DriverName = "Intel Ethernet Diagnostics Driver (Test)",
    [string]$CVE = "CVE-2015-2291"
)

function New-MockDriverFile {
    param(
        [string]$Path,
        [string]$Name,
        [string]$CVEReference
    )
    
    Write-Host "Creating mock vulnerable driver: $Path"
    Write-Host "Simulating: $Name"
    Write-Host "CVE Reference: $CVEReference"
    
    # Create a byte array that resembles a PE file structure
    $peHeader = @(
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,  # MZ header
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    )
    
    # PE signature and headers
    $peSignature = @(0x50, 0x45, 0x00, 0x00)  # PE\0\0
    
    # COFF header for a driver
    $coffHeader = @(
        0x4C, 0x01,  # Machine (i386)
        0x03, 0x00,  # NumberOfSections
        0x00, 0x00, 0x00, 0x00,  # TimeDateStamp (will be set to current time)
        0x00, 0x00, 0x00, 0x00,  # PointerToSymbolTable
        0x00, 0x00, 0x00, 0x00,  # NumberOfSymbols
        0xE0, 0x00,  # SizeOfOptionalHeader
        0x02, 0x21   # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    )
    
    # Optional header (simplified)
    $optionalHeader = @(
        0x0B, 0x01,  # Magic (PE32)
        0x01, 0x00,  # MajorLinkerVersion, MinorLinkerVersion
        0x00, 0x10, 0x00, 0x00,  # SizeOfCode
        0x00, 0x10, 0x00, 0x00,  # SizeOfInitializedData
        0x00, 0x00, 0x00, 0x00,  # SizeOfUninitializedData
        0x00, 0x10, 0x00, 0x00,  # AddressOfEntryPoint
        0x00, 0x10, 0x00, 0x00,  # BaseOfCode
        0x00, 0x00, 0x01, 0x00,  # ImageBase (kernel space)
        0x00, 0x10, 0x00, 0x00,  # SectionAlignment
        0x00, 0x02, 0x00, 0x00,  # FileAlignment
        0x05, 0x00,  # MajorOperatingSystemVersion
        0x01, 0x00,  # MinorOperatingSystemVersion
        0x05, 0x00,  # MajorImageVersion
        0x01, 0x00,  # MinorImageVersion
        0x05, 0x00,  # MajorSubsystemVersion
        0x01, 0x00,  # MinorSubsystemVersion
        0x00, 0x00, 0x00, 0x00,  # Win32VersionValue
        0x00, 0x30, 0x00, 0x00,  # SizeOfImage
        0x00, 0x04, 0x00, 0x00,  # SizeOfHeaders
        0x00, 0x00, 0x00, 0x00,  # CheckSum
        0x01, 0x00,  # Subsystem (NATIVE)
        0x00, 0x00,  # DllCharacteristics
        0x00, 0x10, 0x00, 0x00,  # SizeOfStackReserve
        0x00, 0x10, 0x00, 0x00,  # SizeOfStackCommit
        0x00, 0x10, 0x00, 0x00,  # SizeOfHeapReserve
        0x00, 0x10, 0x00, 0x00,  # SizeOfHeapCommit
        0x00, 0x00, 0x00, 0x00,  # LoaderFlags
        0x10, 0x00, 0x00, 0x00   # NumberOfRvaAndSizes
    )
    
    # Create vulnerability signature
    $vulnSignature = [System.Text.Encoding]::ASCII.GetBytes("VULN_BYOVD_TEST_$CVEReference")
    
    # Driver information strings
    $driverInfo = [System.Text.Encoding]::Unicode.GetBytes(@"
MOCK VULNERABLE DRIVER - $Name
CVE: $CVEReference
Created: $(Get-Date)
Purpose: BYOVD Attack Simulation Testing

SIMULATED VULNERABILITY:
This driver contains a simulated write-what-where vulnerability
that would allow arbitrary kernel memory writes in a real scenario.

ATTACK VECTORS:
- Kernel privilege escalation
- Security software bypass
- Memory corruption exploitation
- Driver signature enforcement bypass

WARNING: This is a test file only - not a real vulnerable driver
"@)
    
    # Combine all components
    $driverBytes = @()
    $driverBytes += $peHeader
    
    # Add padding to reach PE header position (0x80)
    $padding = 0x80 - $peHeader.Length
    $driverBytes += (1..$padding | ForEach-Object { 0x00 })
    
    $driverBytes += $peSignature
    $driverBytes += $coffHeader
    $driverBytes += $optionalHeader
    
    # Add more padding
    $driverBytes += (1..100 | ForEach-Object { 0x00 })
    
    # Add vulnerability signature
    $driverBytes += $vulnSignature
    
    # Add more padding
    $driverBytes += (1..200 | ForEach-Object { 0x41 })  # 'A' characters
    
    # Add driver information
    $driverBytes += $driverInfo
    
    # Add final padding to make it a realistic size (8KB)
    $targetSize = 8192
    $currentSize = $driverBytes.Count
    if ($currentSize -lt $targetSize) {
        $remainingBytes = $targetSize - $currentSize
        $driverBytes += (1..$remainingBytes | ForEach-Object { 
            # Add some random-looking data
            Get-Random -Minimum 0 -Maximum 256 
        })
    }
    
    # Write to file
    try {
        $byteArray = [byte[]]$driverBytes
        [System.IO.File]::WriteAllBytes($Path, $byteArray)
        
        $fileSize = (Get-Item $Path).Length
        Write-Host "Mock driver created successfully!" -ForegroundColor Green
        Write-Host "File: $Path" -ForegroundColor Cyan
        Write-Host "Size: $fileSize bytes" -ForegroundColor Cyan
        
        # Verify file was created correctly
        if (Test-Path $Path) {
            $hash = Get-FileHash -Path $Path -Algorithm SHA256
            Write-Host "SHA256: $($hash.Hash)" -ForegroundColor Yellow
            
            # Display hex dump of first 64 bytes
            Write-Host "`nHex dump (first 64 bytes):" -ForegroundColor Magenta
            $hexBytes = [System.IO.File]::ReadAllBytes($Path)[0..63]
            for ($i = 0; $i -lt $hexBytes.Length; $i += 16) {
                $line = ""
                $ascii = ""
                for ($j = $i; $j -lt [Math]::Min($i + 16, $hexBytes.Length); $j++) {
                    $line += "{0:X2} " -f $hexBytes[$j]
                    $char = [char]$hexBytes[$j]
                    $ascii += if ($char -match '[a-zA-Z0-9]') { $char } else { "." }
                }
                Write-Host ("{0:X4}: {1,-48} {2}" -f $i, $line, $ascii) -ForegroundColor DarkGray
            }
            
            return $true
        } else {
            Write-Host "ERROR: File was not created!" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "ERROR: Failed to create driver file: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
$success = New-MockDriverFile -Path $OutputPath -Name $DriverName -CVEReference $CVE

if ($success) {
    Write-Host "`nMock vulnerable driver created for BYOVD testing" -ForegroundColor Green
    Write-Host "Use this file for testing driver installation and detection capabilities" -ForegroundColor Yellow
    Write-Host "REMEMBER: This is for testing purposes only!" -ForegroundColor Red
} else {
    Write-Host "Failed to create mock driver" -ForegroundColor Red
    exit 1
}