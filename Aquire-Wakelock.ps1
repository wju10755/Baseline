# Device Identification
# PCSystemType values: 1 = Desktop, 2 = Mobile, 3 = Workstation, 4 = Enterprise Server, 5 = SOHO Server, 6 = Appliance PC, 7 = Performance Server, 8 = Maximum

# Get computer system information using CIM (more efficient and modern compared to WMI)
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType
    $manufacturer = $computerSystem.Manufacturer

    # Check if the system is a mobile device
    if ($pcSystemType -eq 2) {
        # Mobile device detected, launching presentation settings
        Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
    } else {
        # Not a mobile device, proceed with wake lock logic
        $flagFilePath = "C:\Temp\WakeLock.flag"
        $wsh = New-Object -ComObject WScript.Shell

        # Infinite loop to keep the system awake
        while ($true) {
            if (Test-Path $flagFilePath) {
                Write-Host "Flag file found. Terminating script..."
                break
            } else {
                Write-Host "Flag file not found. Continuing to prevent sleep mode..."
                $wsh.SendKeys('+{F15}')  # Prevent system sleep by simulating a key press
                Start-Sleep -Seconds 60  # Wait for 60 seconds before the next iteration
            }
        }
    }
} catch {
    Write-Error "Failed to retrieve computer system information. Error: $_"
}
