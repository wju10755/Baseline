Set-Executionpolicy RemoteSigned -Force *> $null

# Start script transcription
Start-Transcript -path c:\temp\$env:ComputerName-Dell_Uninstall.log

# Load System.Windows.Forms assembly
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Keyboard {
    [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
    public static extern IntPtr SetFocus(IntPtr hWnd);

    [DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@


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


# Install Common Stuff 
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

<#
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
        Start-Sleep -Seconds 3
        # Load System.Windows.Forms assembly
        Add-Type -AssemblyName System.Windows.Forms
        # Send the keys
        [System.Windows.Forms.SendKeys]::SendWait("{TAB}{ENTER}")
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
#>
# Remove Dell Display Manager
$DDMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-DDM.zip"
$DDMzip = "C:\temp\Uninstall-DDM.zip"
$DDMdir = "C:\temp\Uninstall-DDM"
Write-Host "Starting Dell bloatware removal`n" -NoNewline
$DDMpackageName = 'Dell Display Manager'
$DDMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue
if ($DDMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    #Write-Host "Downloading Dell Peripheral Manager Script..."
    Invoke-WebRequest -Uri $DDMurl -OutFile $DDMzip *> $null
    Write-Host "Extracting Dell Peripheral Manager package..."
    Expand-Archive -Path $DDMzip -DestinationPath $DDMdir -Force
    Write-Host "Removing Dell Peripheral Manager..."
    & "$DDMdir\Uninstall-DellDisplayManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Log "Removed Dell Display Manager."
} else {
    Write-Host "Dell Display Manager not found" -ForegroundColor "Red"
}

# Remove Dell Pair Application
$programName = "Dell Pair Application"
$uninstallPath = "C:\Program Files\Dell\Dell Pair\Uninstall.exe"

if (Test-Path $uninstallPath) {
    try {
        Write-Host "Removing $programName..." -NoNewline
        $arguments = "`"$uninstallPath`" /S"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c $arguments" -NoNewWindow -Wait -PassThru -ErrorAction Stop *> $null
        Start-Sleep -Seconds 10
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Removed $programName."   
    } catch {
        Write-Warning "Failed to uninstall $programName. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "$programName installation not found." -ForegroundColor "Red"
}


# Remove Dell Peripheral Manager
$DPMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-dpm.zip"
$DPMzip = "C:\temp\Uninstall-dpm.zip"
$DPMdir = "C:\temp\Uninstall-DPM"
$uninstallScript = "$DPMdir\Uninstall-DellPeripheralManager.ps1"

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
            Write-Log "Removed Dell Peripheral Manager."
        } else {
            Write-Warning "Uninstall script not found at $uninstallScript"
        }
    } catch {
        Write-Warning "Failed to remove Dell Peripheral Manager. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}


# Remove Dell Command Update
$DCUURL = "https://advancestuff.hostedrmm.com/labtech/Transfer/installers/remove-dcu.zip"
$DCUZIP = "C:\temp\remove-dcu.zip"
$DCUDEST = "C:\temp\remove-dcu"
$DCUFILE = "C:\temp\remove-dcu\Deploy-DellCommandUpdate.ps1"

try {
    # Download the uninstaller
    Write-Host "Downloading Dell Command Update uninstaller..."
    Invoke-WebRequest -Uri $DCUURL -OutFile $DCUZIP -ErrorAction Stop

    # Extract the uninstaller
    if (Test-Path $DCUZIP) {
        Write-Host "Extracting Dell Command Update uninstaller..."
        Expand-Archive $DCUZIP -DestinationPath $DCUDEST -Force -ErrorAction Stop
    }

    # Run the uninstaller
    if (Test-Path $DCUFILE) {
        Write-Host "Removing Dell Command Update..."
        Powershell.exe -ExecutionPolicy Bypass -File $DCUFILE -DeploymentType "Uninstall" -DeployMode "NonInteractive" *> $null
        Write-Host "Dell Command Update removed successfully."
    } else {
        Write-Warning "Uninstall script not found at $DCUFILE"
    }
} catch {
    Write-Warning "Failed to remove Dell Command Update. Error: $($_.Exception.Message)"
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


# Uninstall Dell Optimizer
$uninstallCommand = '"C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer_MyDell.exe" -remove -runfromtemp -silent'
Start-Process cmd -ArgumentList "/c $uninstallCommand" -Wait


# Uninstall MyDell Suite
$applicationName = 'MyDell'

# Get the uninstall string from the registry
$uninstallString = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
                   Where-Object { $_.DisplayName -eq $applicationName } |
                   Select-Object -ExpandProperty UninstallString

if ($null -ne $uninstallString) {
    try {
        # Modify the uninstall string to run silently and without restarting
        $uninstallString = $uninstallString -Replace '/I', '/X'
        $uninstallString = $uninstallString + ' /qn /norestart'

        # Uninstall the application
        Write-Host "Uninstalling $applicationName..."
        Start-Process cmd -ArgumentList "/c $uninstallString" -Wait -PassThru -ErrorAction Stop
        Write-Host "$applicationName uninstalled successfully." -ForegroundColor "Green"
    } catch {
        Write-Warning "Failed to uninstall $applicationName. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Application '$applicationName' not found." -ForegroundColor "Red"
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
            Write-Warning "There was an error when uninstalling $($package.Name): $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "No matching packages found." -ForegroundColor "Red"
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

Get-CimInstance -Classname Win32_Product | Where-Object Name -Match ‘Dell SupportAssist’ | Invoke-CimMethod -MethodName UnInstall

# Stop Procmon
Stop-Procmon

Stop-Transcript
