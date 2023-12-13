# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    Write-Host "Existing Microsoft Office installation found." -ForegroundColor "Yellow"
} else {
    $FilePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Write-Host "Downloading Microsoft Office..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\OfficeSetup.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        & $officeNotice
        Write-Host "Installing Microsoft Office..." -NoNewline
        Start-Process -FilePath "C:\temp\Officesetup.exe" -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Office 365 Installation Completed Successfully."
        & $clearPath
    }
    else {
        # Report download error
        & $officeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Office download failed!"
        Start-Sleep -Seconds 10
        & $clearPath
        #Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}