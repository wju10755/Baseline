# Remove Dell Display Manager 2.1

$DDM2url = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-DDM2.zip"
$DDM2zip = "C:\temp\Uninstall-DDM2.zip"
$DDM2dir = "C:\temp\Uninstall-DDM2"
Invoke-WebRequest -OutFile c:\temp\Uninstall-DDM2.zip https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-DDM2.zip

if (Test-Path $DDM2zip) {
    if(!(Test-Path -Path "c:\temp\Uninstall-DDM2")) { New-Item -ItemType Directory -Path "c:\temp\Uninstall-DDM2" }
    Expand-Archive -Path $DDM2zip -DestinationPath $DDM2dir -Force
}
set-location "c:\temp\Uninstall-DDM2"
$null = ". .\appdeploytoolkit\AppDeployToolkitMain.ps1 | Out-Null"

Start-Process PowerShell.exe -ArgumentList "-NoExit","-File .\Uninstall-DellDisplayManager.ps1 -DeploymentType Uninstall -DeployMode Interactive"; exit 0
