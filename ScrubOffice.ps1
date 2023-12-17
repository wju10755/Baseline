$OfficeSpinnerURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/OfficeScrub-Spinner.ps1"
$OfficeSpinnerFile = "c:\temp\OfficeScrub-Spinner.ps1"
$OfficeScrubURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/OffScrubc2r.vbs"
$OfficeScrubFile = "c:\temp\OffScrubc2r.vbs"
 
Invoke-WebRequest -Uri $SpinnerURL -OutFile $SpinnerFile -UseBasicParsing -ErrorAction Stop 
Start-Sleep -seconds 1

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
