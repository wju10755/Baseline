Start-Transcript -path c:\temp\$env:ComputerName-Dell_Uninstall.log
# Instal Common Stuff 
$moduleName = "CommonStuff"

# Check if the module is installed
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    #Write-Host "Module '$moduleName' is not installed. Attempting to install..."

    # Attempt to install the module from the PowerShell Gallery
    # This requires administrative privileges
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -Force -ErrorAction Stop
        #Write-Host "Module '$moduleName' installed successfully."
    } catch {
        Write-Error "Failed to install module '$moduleName': $_"
        exit
    }
} else {
    #Write-Host "Module '$moduleName' is already installed."
}
try {
    Import-Module -Name $moduleName -ErrorAction Stop
    #Write-Host "Module '$moduleName' imported successfully."
} catch {
    Write-Error "Failed to import module '$moduleName': $_"
}


# Remove Dell Display Manager
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
$isInstalled = $false
foreach ($path in $registryPaths) {
    $installedPrograms = Get-ItemProperty $path\* -ErrorAction SilentlyContinue
    $dellDisplayManager = $installedPrograms | Where-Object { $_.DisplayName -like "*Dell Display Manager*" }
    if ($dellDisplayManager) {
        $isInstalled = $true
        break
    }
}
if ($isInstalled) {
    Write-Host "Uninstalling Dell Display Manager..."
    Start-Process -FilePath "C:\Program Files\Dell\Dell Display Manager 2\uninst.exe" -ArgumentList "/S", "/v/qn" -Wait -NoNewWindow
    Write-Host " done." -ForegroundColor "Green"
} else {
    Write-Host "Dell Display Manager is not installed."
}


# Remove Dell Pair Application
$pairPath = "C:\Program Files\Dell\Dell Pair\Uninstall.exe"
if (Test-Path $pairPath) {
    Write-Host "Removing Dell Pair Application..." -NoNewline
    $pair = "`"$pairPath`" /S"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $pair" *> $null
    Start-Sleep -Seconds 10
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell Pair Application."   
} else {
    #Write-Host "Dell Pair Uninstall.exe file does not exist."
    Write-Host "Dell Pair installation not found." -ForegroundColor "Red"
}


# Remove Dell Peripheral Manager
$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm.zip"
$DPMzip = "C:\temp\Uninstall-dpm.zip"
$DPMdir = "C:\temp\Uninstall-DPM"
Write-Host "Starting Dell bloatware removal`n" -NoNewline
$DPMpackageName = 'Dell Peripheral Manager'
$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue
if ($DPMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    #Write-Host "Downloading Dell Peripheral Manager Script..."
    Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip *> $null
    Write-Host "Extracting Dell Peripheral Manager package..."
    Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force
    Write-Host "Removing Dell Peripheral Manager..."
    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

# Remove Dell Command | Update for Windows Universal
$DCUURL = "https://advancestuff.hostedrmm.com/labtech/Transfer/installers/remove-dcu.zip"
$DCUZIP = "C:\temp\remove-dcu.zip"
$DCUDEST = "c:\temp\remove-dcu"
$DCUFILE = "C:\temp\remove-dcu\Deploy-DellCommandUpdate.ps1"
Invoke-WebRequest -Uri $DCUURL -OutFile $DCUZIP
if (Test-Path $DCUZIP){
Expand-Archive $DCUZIP -DestinationPath $DCUDEST -force

if (Test-Path $DCUFILE) {
Powershell.exe -ExecutionPolicy Bypass .\Deploy-DellCommandUpdate.ps1 -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null
}
}


# Trigger remaining Dell application uninstall
$SWName = Get-InstalledSoftware "Dell", "Microsoft Update Health Tools", "ExpressConnect Drivers & Services" |
    Where-Object { $_.DisplayName -ne "Dell Trusted Device Agent" } |  
    Select-Object -ExpandProperty DisplayName
if ($SWName) {
    try {
        foreach ($name in $SWName) {
            $param = @{
                Name        = $name
                ErrorAction = "Stop"
            }

            if ($name -eq "Dell Optimizer Core") {
                # uninstallation isn't unattended without -silent switch
                $param["addArgument"] = "-silent"
            }

            Uninstall-ApplicationViaUninstallString @param
        }
    } catch {
        Write-Error "There was an error when uninstalling bloatware: $_"
    }
} else {
    "There is no bloatware detected"
}

# Trigger uninstall of remaining Dell applications
$Remaining = Get-Package | Where-Object {
    $_.Name -like 'Dell Trusted Device Agent' -and
    $_.Name -notlike '*firmware*' -and
    $_.Name -notlike '*WLAN*' -and
    $_.Name -notlike '*HID*' -and
    $_.Name -notlike '*Touch*'
  }
    
  foreach ($package in $Remaining) {
    Write-Host "Triggering uninstall for $($package.Name)" -NoNewline
    Uninstall-Package -Name $package.Name -Force *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed $($package.Name)"
  }
  

Stop-Transcript
