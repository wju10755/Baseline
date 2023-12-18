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
        Start-Process -FilePath "cscript.exe" -ArgumentList "$OfficeScrubFile ALL /Quiet /NoCancel" -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Pre-installed versions of Microsoft Office 365 successfully uninstalled."
 
        Start-Sleep -Seconds 15
        
    } else {
        Write-Host "Failed to download Office Scrub script." -ForegroundColor "Red"
        Write-Log "Failed to download Office Scrub script."
    }
