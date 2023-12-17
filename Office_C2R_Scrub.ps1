$OfficeSpinnerURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeScrub-Spinner.ps1"
$OfficeSpinnerFile = "c:\temp\OfficeScrub-Spinner.ps1"
$OfficeScrubURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OffScrubc2r.vbs"
$OfficeScrubFile = "c:\temp\OffScrubc2r.vbs"
 
Invoke-WebRequest -Uri $OfficeScrubURL -OutFile $OfficeScrubFile -UseBasicParsing -ErrorAction Stop
if (Test-Path $OfficeScrubFile) {
Invoke-WebRequest -Uri $OfficeSpinnerURL -OutFile $OfficeSpinnerFile -UseBasicParsing -ErrorAction Stop
    if (Test-Path $OfficeScrubFile) {
    Start-Process -FilePath "cscript.exe" -ArgumentList "$OfficeScrubFile ALL /Quiet /NoCancel" -Wait
    }
} else {
Write-Host "Office C2R Scrub utility download failed"
}