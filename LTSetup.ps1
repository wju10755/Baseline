$tmp = "C:\temp"
$LTPKG = "C:\temp\Warehouse_Agent_MSI_Install.zip"
$LTURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse_Agent_MSI_Install.zip"
$LTBAT = "C:\temp\install.bat"

Write-Host "Starting LTAgent Setup...."
for ($i = 30; $i -ge 0; $i--) {
	Write-Host -NoNewline "`r$i seconds remaining..."
	Start-Sleep -Seconds 1
}

if (-Not (Test-Path -Path $tmp)) {
	New-Item -Path $tmp -ItemType Directory
}


Invoke-WebRequest -Uri $LTURL -OutFile $LTPKG

Start-Sleep -Seconds 5

Expand-Archive -Path $LTPKG -DestinationPath $tmp

Start-Sleep -5

Start-Process $LTBAT -Wait


