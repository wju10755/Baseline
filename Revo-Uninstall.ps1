$RevoURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/RevoCMD.zip"
$RevoFile = "c:\temp\RevoCMD.zip"
$RevoDestination = "c:\temp\RevoCMD"

# Download RevoCMD.zip
Invoke-WebRequest -Uri $RevoURL -OutFile $RevoFile -ErrorAction SilentlyContinue

# Check if RevoCMD.zip exists
if (Test-Path -Path $RevoFile) {
    # Extract RevoCMD.zip
    Expand-Archive -Path $RevoFile -DestinationPath $RevoDestination -Force
    
    # Run RevoUnPro with specified parameters
    Start-Process -FilePath "$RevoDestination\RevoUnPro.exe" -ArgumentList "/mu 'Dell SupportAssist' /path 'C:\Program Files\Dell\SupportAssistAgent' /mode Moderate /32"
}
