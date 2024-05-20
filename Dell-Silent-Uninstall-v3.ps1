Set-Executionpolicy RemoteSigned -Force *> $null
# Start script transcription
Start-Transcript -path c:\temp\$env:ComputerName-Dell_Uninstall.log

# Common Stuff Module
$moduleName = "CommonStuff"

# Move the procmon process window to top left
function Move-ProcessWindowToTopLeft([string]$processName) {
    $process = Get-Process | Where-Object { $_.ProcessName -eq $processName } | Select-Object -First 1
    if ($null -eq $process) {
        Write-Host "Process not found."
        return
    }

    $hWnd = $process.MainWindowHandle
    if ($hWnd -eq [IntPtr]::Zero) {
        Write-Host "Window handle not found."
        return
    }

    $windowRect = New-Object WinAPI+RECT
    [WinAPI]::GetWindowRect($hWnd, [ref]$windowRect)
    $windowWidth = $windowRect.Right - $windowRect.Left
    $windowHeight = $windowRect.Bottom - $windowRect.Top

    # Set coordinates to the top left corner of the screen
    $x = 0
    $y = 0

    [WinAPI]::MoveWindow($hWnd, $x, $y, $windowWidth, $windowHeight, $true)
}

# Define the function to start Procmon
function Start-Procmon {
    $ps = Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
    $wshell = New-Object -ComObject wscript.shell
    Start-Sleep -Seconds 3
    $wshell.SendKeys("^a")
    Start-Sleep -Seconds 2

    Move-ProcessWindowToTopLeft -processName "procmon64" *> $null
}

# Define the function to stop Procmon
function Stop-Procmon {
    $wshell = New-Object -ComObject wscript.shell
    $wshell.SendKeys("^a")
    Start-Sleep -Seconds 2
    taskkill /f /im procmon* *> $null
}


# Check if the module is installed
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    #Write-Host "Module '$moduleName' is not installed. Attempting to install..."

    # Attempt to install the module from the PowerShell Gallery
    # This requires administrative privileges
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
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


# Start Procmon
Start-Procmon

Start-Sleep -Seconds 5




# Remove Dell Display Manager 2.1
$DDM2url = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-DDM2.zip"
$DDM2url = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Start-DDM2.ps1"

$DDM2zip = "C:\temp\Uninstall-DDM2.zip"
$DDM2dir = "C:\temp\Uninstall-DDM2"
Invoke-WebRequest -OutFile c:\temp\Uninstall-DDM2.zip https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-DDM2.zip
Invoke-WebRequest -OutFile c:\temp\Start-DDM2.ps1 https://advancestuff.hostedrmm.com/labtech/transfer/installers/Start-DDM2.ps1

if (Test-Path $DDM2zip) {
    if(!(Test-Path -Path "c:\temp\Uninstall-DDM2")) { New-Item -ItemType Directory -Path "c:\temp\Uninstall-DDM2" }
    Expand-Archive -Path $DDM2zip -DestinationPath $DDM2dir -Force
}
set-location "c:\temp\Uninstall-DDM2"
$null = ". .\appdeploytoolkit\AppDeployToolkitMain.ps1 | Out-Null"

#Start-Process PowerShell.exe -ArgumentList "-NoExit","-File .\Uninstall-DellDisplayManager.ps1 -DeploymentType Uninstall -DeployMode Interactive"; exit 0
Start-Process Powershell.exe -ArgumentList "-NoExit","-File .\Start-DDM2.ps1" -WindowStyle Minimized

# Start Dell Software Uninstall
$applicationList = "Dell", "Microsoft Update Health Tools", "ExpressConnect Drivers & Services"

# Get the list of installed software
$installedSoftware = Get-InstalledSoftware $applicationList |
    Where-Object { $_.DisplayName -ne "Dell Trusted Device Agent" } |
    Select-Object -ExpandProperty DisplayName

if ($installedSoftware) {
    foreach ($software in $installedSoftware) {
        try {
            $params = @{
                Name        = $software
                ErrorAction = "Stop"
            }

            if ($software -eq "Dell Optimizer Core") {
                # uninstallation isn't unattended without -silent switch
                $params["addArgument"] = "-silent"
            }

            # Uninstall the software
            Write-Host "Uninstalling $software..."
            Uninstall-ApplicationViaUninstallString @params
            Write-Host "$software uninstalled successfully." -ForegroundColor "Green"
        } catch {
            Write-Warning "Failed to uninstall $software. Error: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "No bloatware detected." -ForegroundColor "Red"
}

# Remove Dell Peripheral Manager
$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm2.zip"
$DPMzip = "C:\temp\Uninstall-dpm2.zip"
$DPMdir = "C:\temp\Uninstall-DPM2"
$uninstallScript = "$DPMdir\Uninstall-DellPeripheralManager2.ps1"

Write-Host "Starting Dell bloatware removal`n" -NoNewline

$DPMpackageName = 'Dell Peripheral Manager'
$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue

if ($DPMpackage) {
    try {
        # Download Dell Peripheral Manager
        $ProgressPreference = 'SilentlyContinue'
        Write-Host "Downloading Dell Peripheral Manager Script..."
        Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip -ErrorAction Stop

        Write-Host "Extracting Dell Peripheral Manager package..."
        Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force -ErrorAction Stop

        if (Test-Path $uninstallScript) {
            Write-Host "Removing Dell Peripheral Manager..."
            & $uninstallScript -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null  
            Write-Host "Removed Dell Peripheral Manager."
        } else {
            Write-Warning "Uninstall script not found at $uninstallScript"
        }
    } catch {
        Write-Warning "Failed to remove Dell Peripheral Manager. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

# Trigger remaining Dell application uninstall
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