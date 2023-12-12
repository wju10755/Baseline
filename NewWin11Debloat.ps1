# Function to check if the OS is Windows 11
function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

# Check if the OS is Windows 11
if (Is-Windows11) {
    try {
        # Your Windows 11 specific code here
        # Download Win11Debloat.ps1
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11Spinner -UseBasicParsing -ErrorAction Stop
        Start-Sleep -seconds 1
        if (Test-Path -Path $Win11DebloatFile) {
            Expand-Archive $Win11DebloatFile -DestinationPath c:\temp\Win11Debloat
            & 'C:\temp\Win11Debloat\Win11Debloat\Win11Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent
        }
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    Write-Host "This script is intended to run only on Windows 11."
}