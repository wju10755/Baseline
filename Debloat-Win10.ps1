# Function to check if the OS is Windows 10
function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

# Check if the OS is Windows 10
if (Is-Windows10) {
    try {
        $MITS10DebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $MITS10DebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $MITS10DebloatURL -OutFile $MITS10DebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $MITS10DebloatFile -DestinationPath 'c:\temp\MITS-Debloat' -Force
        Start-Sleep -Seconds 2
        & 'C:\temp\MITS-Debloat\MITS-Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    Write-Host "This script is intended to run only on Windows 10."
}
