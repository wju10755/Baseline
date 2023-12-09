$NoSnooze = "c:\temp\NoSnooze.ps1"
$DownloadUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NoSnooze.zip"
$DownloadPath = "c:\temp\NoSnooze.zip"
$DestinationPath = "c:\temp"

try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath -ErrorAction Stop
    Expand-Archive -Path $DownloadPath -DestinationPath $DestinationPath -ErrorAction Stop
    Set-Location $DestinationPath
    & $NoSnooze
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}
