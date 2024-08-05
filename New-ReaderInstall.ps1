# Define the URL and file path for the Acrobat Reader installer
$URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Reader_en_install.exe"
$AcroFilePath = "C:\temp\Reader_en_install.exe"

# Download the Acrobat Reader installer
$ProgressPreference = 'SilentlyContinue'
$response = Invoke-WebRequest -Uri $URL -Method Head
$fileSize = $response.Headers["Content-Length"]
$ProgressPreference = 'Continue'
Write-Host "Downloading Adobe Acrobat Reader ($fileSize bytes)..."
Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing

# Start the silent installation of Acrobat Reader
Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /rps /msi /norestart /quiet" -NoNewWindow
Start-sleep -Seconds 240
# Monitor the system for the active msiexec.exe process
Write-Host "Monitoring for msiexec.exe process..."
do {
    Start-Sleep -Seconds 10
    $msiexecProcess = Get-Process -Name msiexec -ErrorAction SilentlyContinue
} while ($msiexecProcess)

# Once msiexec.exe process exits, kill the Reader_en_install.exe process
Write-Host "msiexec.exe process has exited. Terminating Reader_en_install.exe..."
Stop-Process -Name Reader_en_install -Force -ErrorAction SilentlyContinue
Stop-Process -Name MSEDGE -Force -ErrorAction SilentlyContinue

Write-Host "Adobe Acrobat Reader installation complete."