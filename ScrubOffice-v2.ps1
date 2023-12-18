$OfficeSpinnerURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeScrub_Spinner.ps1"
$OfficeSpinnerFile = "c:\temp\OfficeScrub-Spinner.ps1"
$OfficeScrubScriptURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/ScrubOffice.ps1"
$OfficeScrubScriptFile = "c:\temp\ScrubOffice.ps1" 
$OfficeScrubURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OffScrubc2r.vbs"
$OfficeScrubFile = "c:\temp\OffScrubc2r.vbs"


# Verify requried files exist
if (-NOT (Test-Path $OfficeScrubFile)) {
    Write-Host "Downloading required file..." 
    Invoke-WebRequest -Uri $OfficeScrubURL -OutFile $OfficeScrubFile -UseBasicParsing -ErrorAction Stop 
}

if (-NOT (Test-Path $OfficeScrubScriptFile)) {
    Write-Host "Downloading required file..."
    Invoke-WebRequest -Uri $OfficeScrubScriptURL -OutFile OfficeScrubScriptFile -UseBasicParsing -ErrorAction Stop

}

if (-NOT (Test-Path $OfficeSpinnerFile)) {
    Write-Host "Downloading required file..." 
    Invoke-WebRequest -Uri $OfficeSpinnerURL -OutFile $OfficeSpinnerFile -UseBasicParsing -ErrorAction Stop 
}

# Validate successful download by checking the file size
$FileSize = (Get-Item $OfficeScrubFile).Length
$ExpectedSize = 146093 # in bytes 
if ($FileSize -eq $ExpectedSize) {

    Write-Host "Scrubbing pre-installed versions of Office..." -NoNewline
    Start-Process -FilePath "cscript.exe" -ArgumentList "$OfficeScrubFile ALL /Quiet /NoCancel"
    Start-Sleep -Seconds 60
    while ($true) {
    # Get the count of cscript.exe processes
    $processCount = (Get-Process cscript -ErrorAction SilentlyContinue).Count
    Start-Sleep -Seconds 5
    # Check if the process count is 1
    if ($processCount -eq 1) {
        # Kill the remaining cscript.exe process
        taskkill /f /im cscript.exe

        # Break the loop after killing the process
        break
        }
        
    # Optional: Wait for a bit before checking again to reduce CPU usage
    Start-Sleep -Seconds 5
    }    
    Write-Host " done." -ForegroundColor "Green"
    #Write-Log "Pre-installed versions of Microsoft Office 365 successfully uninstalled."

    Start-Sleep -Seconds 15

} else {
    Write-Host "Failed to download Office Scrub script." -ForegroundColor "Red"
    #Write-Log "Failed to download Office Scrub script."
}


# Infinite loop to keep checking the cscript.exe process count


# Script ends here
