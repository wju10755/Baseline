# Name of the module
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

# Import the module
try {
    Import-Module -Name $moduleName -ErrorAction Stop
    #Write-Host "Module '$moduleName' imported successfully."
} catch {
    Write-Error "Failed to import module '$moduleName': $_"
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

$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm.zip"
$DPMzip = "C:\temp\Uninstall-dpm.zip"
$DPMdir = "C:\temp\Uninstall-DPM"

# Check if Dell Peripheral Manager is installed
Write-Host "Starting Dell bloatware removal`n" -NoNewline
$DPMpackageName = 'Dell Peripheral Manager'
$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue

if ($DPMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    #Write-Host "Downloading Dell Peripheral Manager Script..."
    Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip *> $null

    # Extract the file
    Write-Host "Extracting Dell Peripheral Manager package..."
    Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force

    # Run the script
    Write-Host "Removing Dell Peripheral Manager..."
    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

# Check if Dell Display Manager is installed
#$DDMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-ddm.zip"
#$DDMzip = "C:\temp\Uninstall-ddm.zip"
#$DDMdir = "C:\temp\Uninstall-DDM"
#$DDMpackageName = 'Dell Display Manager'

#$DDMpackage = Get-Package -Name $DDMpackageName -ErrorAction SilentlyContinue

#if ($DDMpackage) {
#    # Download Dell Peripheral Manager
#    $ProgressPreference = 'SilentlyContinue'
#    Invoke-WebRequest -Uri $DDMurl -OutFile $DDMzip *> $null
#
#    # Extract the file
#    Write-Host "Extracting Dell Display Manager package..."
#    Expand-Archive -Path $DDMzip -DestinationPath $DDMdir -Force
#
#    # Run the script
#    Write-Host "Removing Dell Display Manager..." -NoNewline
#    & "$DDMdir\Uninstall-DellDisplayManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
#    Write-Host " done." -ForegroundColor "Green"
#    Write-Log "Removed Dell Display Manager."
#} else {
#    Write-Host "Dell Display Manager not found" -ForegroundColor "Red"
#}

# Define the registry paths for installed programs
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# Check if Dell Display Manager is installed
$isInstalled = $false
foreach ($path in $registryPaths) {
    $installedPrograms = Get-ItemProperty $path\* -ErrorAction SilentlyContinue
    $dellDisplayManager = $installedPrograms | Where-Object { $_.DisplayName -like "*Dell Display Manager*" }
    if ($dellDisplayManager) {
        $isInstalled = $true
        break
    }
}

# Output the result
if ($isInstalled) {
    Write-Host "Uninstalling Dell Display Manager..."
    Start-Process -FilePath "C:\Program Files\Dell\Dell Display Manager 2\uninst.exe" -ArgumentList "/S", "/v/qn" -Wait -NoNewWindow
    Write-Host " done." -ForegroundColor "Green"
} else {
    Write-Host "Dell Display Manager is not installed."
}


$softwarePaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$isInstalled = $false
$uninstallCommand = "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe"

foreach ($path in $softwarePaths) {
    $software = Get-ItemProperty $path\* -ErrorAction SilentlyContinue
    $dellOptimizerCore = $software | Where-Object { $_.DisplayName -like "*Dell Optimizer Core*" }
    if ($dellOptimizerCore) {
        $isInstalled = $true
        break
    }
}

if ($isInstalled) {
    Start-Process -FilePath $uninstallCommand -ArgumentList "-remove -runfromtemp -silent" -Wait -NoNewWindow
}


$SWName = Get-InstalledSoftware "Dell", "Microsoft Update Health Tools", "ExpressConnect Drivers & Services" | 
    Where-Object { $_.DisplayName -ne "Dell Pair" } | 
    Select-Object -ExpandProperty DisplayName

if ($SWName) {
    try {
        foreach ($name in $SWName) {
            $param = @{
                Name        = $name
                ErrorAction = "Stop"
            }

            if ($name -eq "Dell Optimizer Service") {
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
