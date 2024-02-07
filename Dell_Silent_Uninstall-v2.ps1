Set-Executionpolicy RemoteSigned -Force *> $null

# Start script transcription
Start-Transcript -path c:\temp\$env:ComputerName-Dell_Uninstall.log

# Check if the system manufacturer is Dell
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
if ($manufacturer -notlike "*Dell*") {
    $DellOnly = "This module is only eligible for genuine Dell systems."
    foreach ($Char in $DellOnly.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 50
    }
    Stop-Transcript
    break
}


# Instal Common Stuff 
$moduleName = "CommonStuff"

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

# Download Procmon
$ProgressPreference = 'SilentlyContinue'
$ProcmonURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Procmon.exe"
$ProcmonFile = "c:\temp\Procmon.exe"
Invoke-WebRequest -Uri $ProcmonURL -OutFile $ProcmonFile *> $null

# Launch Procmon and enable auto-scroll
$ps = Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
$wshell = New-Object -ComObject wscript.shell
Start-Sleep -Seconds 3
$wshell.SendKeys("^a")
Start-Sleep -Seconds 2

# Move Procmon left
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinAPI {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
    }
"@

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

Move-ProcessWindowToTopLeft -processName "procmon64" *> $null


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
    try {
        Write-Host "Uninstalling Dell Display Manager..."
        $process = Start-Process -FilePath "C:\Program Files\Dell\Dell Display Manager 2\uninst.exe" -ArgumentList "/S", "/v/qn" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($process.ExitCode -eq 0) {
            Write-Host "Successfully uninstalled Dell Display Manager." -ForegroundColor "Green"
        } else {
            Write-Warning "Failed to uninstall Dell Display Manager. Exit code: $($process.ExitCode)"
        }
    } catch {
        Write-Warning "Failed to uninstall Dell Display Manager. Error: $($_.Exception.Message)"
    }
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
    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

# Remove Dell Command Update
$DCUURL = "https://advancestuff.hostedrmm.com/labtech/Transfer/installers/remove-dcu.zip"
$DCUZIP = "C:\temp\remove-dcu.zip"
$DCUDEST = "C:\temp\remove-dcu"
$DCUFILE = "C:\temp\remove-dcu\Deploy-DellCommandUpdate.ps1"

# Download the uninstaller
Invoke-WebRequest -Uri $DCUURL -OutFile $DCUZIP

# Extract the uninstaller
if (Test-Path $DCUZIP) {
    Expand-Archive $DCUZIP -DestinationPath $DCUDEST -Force
}

# Run the uninstaller
if (Test-Path $DCUFILE) {
    Powershell.exe -ExecutionPolicy Bypass -File $DCUFILE -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null
}


# Remove Dell Peripheral Manager
#$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm.zip"
#$DPMzip = "C:\temp\Uninstall-dpm.zip"
#$DPMdir = "C:\temp\Uninstall-DPM"
#Write-Host "Starting Dell bloatware removal`n" -NoNewline
#$DPMpackageName = 'Dell Peripheral Manager'
#$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue
#if ($DPMpackage) {
#    # Download Dell Peripheral Manager
#    $ProgressPreference = 'SilentlyContinue'
#    #Write-Host "Downloading Dell Peripheral Manager Script..."
#    Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip *> $null
#    Write-Host "Extracting Dell Peripheral Manager package..."
#    Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force
#    Write-Host "Removing Dell Peripheral Manager..."
#    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
#    Write-Log "Removed Dell Peripheral Manager."
#} else {
#    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
#}


# Remove Dell Peripheral Manager
$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm2.zip"
$DPMzip = "C:\temp\Uninstall-dpm2.zip"
$DPMdir = "C:\temp\Uninstall-DPM2"
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
    & "$DPMdir\Uninstall-DellPeripheralManager2.ps1" -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}



# Uninstall Dell Optimizer
$uninstallCommand = '"C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer_MyDell.exe" -remove -runfromtemp -silent'
Start-Process cmd -ArgumentList "/c $uninstallCommand" -Wait


# Uninstall MyDell
$uninstallString = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
                   Where-Object { $_.DisplayName -eq 'MyDell' } |
                   Select-Object -ExpandProperty UninstallString
if ($null -ne $uninstallString) {
    # Uninstall the application
    $uninstallString = $uninstallString -Replace '/I', '/X'
    $uninstallString = $uninstallString + ' /qn /norestart'
    Start-Process cmd -ArgumentList "/c $uninstallString" -Wait
} else {
    Write-Host "Application 'My Dell' not found."
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


# Define the list of package names to exclude
$excludeNames = @('*firmware*', '*WLAN*', '*HID*', '*Touch*')

# Get the remaining Dell packages
$remainingPackages = Get-Package | Where-Object {
    $_.Name -like 'Dell Trusted Device Agent' -and
    $excludeNames -notcontains $_.Name
}

# Check if any packages were found
if ($remainingPackages) {
    # Uninstall each package
    foreach ($package in $remainingPackages) {
        try {
            Write-Host "Triggering uninstall for $($package.Name)" -NoNewline
            Uninstall-Package -Name $package.Name -Force -ErrorAction Stop *> $null
            Write-Host " done." -ForegroundColor "Green"
            Write-Log "Removed $($package.Name)"
        } catch {
            Write-Error "There was an error when uninstalling $($package.Name): $_"
        }
    }
} else {
    Write-Host "No matching packages found."
}

# Get applications with a name like 'Dell'
$dellApps = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like '*Dell*' }

# Uninstall each application
foreach ($app in $dellApps) {
    $appName = $app.Name
    Write-Host "Attempting to uninstall: [$appName]..."
    $uninstallResult = Invoke-CimMethod -InputObject $app -MethodName "Uninstall"
    if ($uninstallResult.ReturnValue -eq 0) {
        Write-Host "Successfully uninstalled: [$appName]"
    } else {
        Write-Warning "Failed to uninstall: [$appName]. Exit code: $($uninstallResult.ReturnValue)"
    }
}

$wshell.SendKeys("^a")
Start-Sleep -Seconds 2  
taskkill /f /im procmon* *> $null
Stop-Transcript
