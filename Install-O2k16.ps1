# Install Office 2016
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft Office Professional Plus 2016*" }

if ($O365) {
    Write-Host "Existing Microsoft Office 2016 installation found." -ForegroundColor "Cyan"
} else {
    $FilePath = "C:\temp\O2k16pp.zip"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        Write-Host "Downloading Microsoft Office 2016 (757,921,585 bytes)..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\O2k16pp.zip -Uri "https://skgeneralstorage.blob.core.windows.net/o2k16pp/O2k16pp.zip" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 757921585 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        & $officeNotice
        Expand-Archive -path c:\temp\O2k16pp.zip -DestinationPath 'c:\temp\' -Force
        Write-Host "Installing Microsoft Office 2016..." -NoNewline
        $OfficeInstaller = "C:\temp\Office2016_ProPlus\setup.exe"
        $OfficeArguments = "/adminfile .\SLaddInstallOffice.msp"
        Set-Location -path 'C:\temp\Office2016_ProPlus\'
        Start-Process -FilePath $OfficeInstaller -ArgumentList $OfficeArguments -Wait    
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Office 365 Installation Completed Successfully."
        & $clearPath
    }
    else {
        # Report download error
        & $officeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Office 2016 download failed!"
        Start-Sleep -Seconds 10
        & $clearPath
        #Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}
