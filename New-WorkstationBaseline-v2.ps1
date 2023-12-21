Clear-Host
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline;
    Write-Host -ForegroundColor $Color $Message;
}

# Print Script Title
#################################
$Padding = ("=" * [System.Console]::BufferWidth);
Write-Host -ForegroundColor "Red" $Padding -NoNewline;
Print-Middle "MITS - New Workstation Baseline Utility";
Write-Host -ForegroundColor "Red" -NoNewline $Padding;
Write-Host " "
Set-ExecutionPolicy -Scope process RemoteSigned -Force

Start-Transcript -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt


# Central Configuration
$config = @{
    AcrobatComplete      = "c:\temp\psnotice\appnotice\acrobat\AcrobatComplete.ps1"
    AcrobatFailure       = "C:\temp\psnotice\appnotice\acrobat\failure\New-ToastNotification.ps1"
    AcrobatInstaller     = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    AutomateFailure      = "C:\temp\psnotice\AppNotice\automate\failure\New-ToastNotification.ps1"
    AutomateSuccess      = "C:\temp\psnotice\AppNotice\automate\"
    BaselineComplete     = "C:\temp\psnotice\BaselineComplete\New-ToastNotification.ps1"
    Checkpoint           = "C:\temp\psnotice\checkpoint\New-ToastNotification.ps1"
    ChromeInstaller      = "c:\temp\ChromeSetup.exe"
    ChromeNotification   = "C:\temp\psnotice\appnotice\Chrome\New-ToastNotification.ps1"
    ClearPath            = "C:\temp\psnotice\Clear-ToastNotification.ps1"
    DebloatSpinner       = "C:\temp\Win11Debloat_Spinner.ps1"
    DellBloatware        = "C:\temp\psnotice\DellNotice\New-ToastNotification.ps1"
    DellHardware         = "C:\temp\psnotice\hardware-dell"
    FastStartup          = "C:\temp\psnotice\FastStartup\New-ToastNotification.ps1"
    HiberSleep           = "C:\temp\psnotice\HiberSleep\New-ToastNotification.ps1"
    HardwareMFG          = "C:\temp\psnotice\Hardware-Dell\New-ToastNotification.ps1"
    LidAction            = "C:\temp\psnotice\LidClose\New-ToastNotification.ps1"
    LogFile              = "C:\temp\baseline.log"
    NoSnooze             = "c:\temp\nosnooze.ps1"
    NoSnoozeUrl          = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NoSnooze.zip"
    NoSnoozeZip          = "c:\temp\nosnooze.zip"
    OfficeComplete       = "C:\temp\psnotice\OfficeNotice\complete\New-ToastNotification.ps1"
    OfficeFailure        = "C:\temp\psnotice\OfficeNotice\failure\New-ToastNotification.ps1"
    OfficeInstaller      = "c:\temp\Office2016_ProPlus"
    PowerProfile         = "C:\temp\psnotice\powerprofile\New-ToastNotification.ps1"
    PSNoticeFile         = "c:\temp\psnotice.zip"
    PSNoticePath         = "c:\temp\PSNotice"
    PSNoticeUrl          = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/psnotice.zip"
    ScrubOffice          = "C:\temp\psnotice\scruboffice\New-ToastNotification.ps1"
    StartBaseline        = "C:\temp\psnotice\BaselineStart\New-ToastNotification.ps1"
    SystemRestore        = "C:\temp\psnotice\SystemRestore\New-ToastNotification.ps1"
    TempFolder           = "C:\temp"
    TimeZone             = "C:\temp\psnotice\TimeZone\New-ToastNotification.ps1"
    UpdateComplete       = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    UpdateNotice         = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    Win10                = "C:\temp\psnotice\win10\New-ToastNotification.ps1"
    Win11                = "C:\temp\psnotice\win11\New-ToastNotification.ps1"
}


# Create temp directory and baseline log
function Initialize-Environment {
    if (-not (Test-Path $config.TempFolder)) {
        New-Item -Path $config.TempFolder -ItemType Directory | Out-Null
    }
    if (-not (Test-Path $config.LogFile)) {
        New-Item -Path $config.LogFile -ItemType File | Out-Null
    }
}

# Baseline Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $config.LogFile -Value "$(Get-Date) - $Message"
}

# Check if the system type is a laptop (Mobile or Notebook)
$computerSystem = Get-WmiObject Win32_ComputerSystem
$manufacturer = $computerSystem.Manufacturer

# PCSystemType values: 1 = Desktop, 2 = Mobile, 3 = Workstation, 4 = Enterprise Server, 5 = SOHO Server, 6 = Appliance PC, 7 = Performance Server, 8 = Maximum
if ($computerSystem.PCSystemType -eq 2) {
    # It's a laptop, run the specified command
    Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
} else {
    # It's not a laptop, continue to the next part of the script
    #Write-Host "This is a Desktop or other non-laptop system. Continuing with the next part of the script."
}

Write-Output " "
Write-Output " "
Write-Host "Starting workstation baseline..." -ForegroundColor "Yellow"   
Write-Output " "
Start-Sleep -Seconds 2
Write-Host "Installing required powershell modules..." -NoNewline
# Check and Install NuGet Provider if not found
if (-not (Get-PackageSource -Name 'NuGet' -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet  -Scope CurrentUser -Force | Out-Null
    Import-PackageProvider -Name NuGet -Force | Out-Null
    Register-PackageSource -Name NuGet -ProviderName NuGet -Location https://www.nuget.org/api/v2 -Trusted | Out-Null
    
}

# Check and install BurntToast Module if not found
if (-not (Get-Module -Name BurntToast -ErrorAction SilentlyContinue)) {
    Install-Module -Name BurntToast -Scope CurrentUser -Force -WarningAction SilentlyContinue | Out-Null
    Import-Module BurntToast 
    Write-Host " done." -ForegroundColor Green
}


# Stop & disable the Windows Update service
Write-Host "Suspending windows Update during baseline process..." -NoNewline
Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled
Start-Sleep -Seconds 3
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
    Write-Host " done." -ForegroundColor Green
} else {
    Write-Host " failed." -ForegroundColor Red
}

# Check and install BurntToast Module if not found
if (-not (Get-Module -Name BurntToast -ErrorAction SilentlyContinue)) {
    Install-Module -Name BurntToast -Scope CurrentUser -Force -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
}
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() # Reset the color to default
[Console]::WriteLine() # Move to the next line

# Stage Toast Notifications
[Console]::Write("Staging notifications...")
$ProgressPreference = 'Continue'
$url = $config.PSNoticeURL
$filePath = $config.PSNoticeFile

if (-not (Test-Path -Path $filePath -PathType Leaf)) {
    Invoke-WebRequest -Uri $url -OutFile $filePath
} else {
}

if (Test-Path -Path $config.PSNoticeFile -PathType Leaf) {
    Expand-Archive -Path $config.PSNoticeFile -DestinationPath $config.PSNoticePath -Force
}

[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() 
[Console]::WriteLine() 

# Disable Notification Snooze
Add-Type -AssemblyName System.Windows.Forms
Start-Sleep -Seconds 5
Invoke-WebRequest -uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/SendWKey.exe" -OutFile "c:\temp\SendWKey.exe"
$sendWKeyPath = "C:\temp\SendWKey.exe"

# Define the arguments for SendWKey.exe
$arguments = '#{n}'

# Execute SendWKey.exe with the arguments
Start-Process -FilePath $sendWKeyPath -ArgumentList $arguments -NoNewWindow -Wait

Start-Sleep -Seconds 1

# Send the Space keystroke
[System.Windows.Forms.SendKeys]::SendWait(' ')
[System.Windows.Forms.SendKeys]::SendWait('{ESC}')

# Start Baseline Notification
& $config.StartBaseline | Out-Null
Write-Log "Automated workstation baseline has started"

# Identify device manufacturer and chassis type
$computerSystem = Get-WmiObject Win32_ComputerSystem
$manufacturer = $computerSystem.Manufacturer
$deviceType = if ($computerSystem.PCSystemType -eq 2) { "Laptop" } else { "Desktop" }
Write-Host "Identifying device type: " -NoNewline
Start-Sleep -Seconds 2
Write-Host $deviceType -ForegroundColor "Yellow"
Write-Log "Manufacturer: $manufacturer, Device Type: $deviceType."


# ConnectWise Automate Agent Installation
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"
#& $config.ClearPath
if (-not (Test-Path $file)) {
    #Write-Host "Downloading ConnectWise Automate Remote Agent..." -NoNewline
    Invoke-WebRequest -Uri $installerUri -OutFile $file -ErrorAction SilentlyContinue
}

# Verify dowload
if (Test-Path $file) {
    #Write-Host " done." -ForegroundColor Green
} else {
    Write-Host " failed!" -ForegroundColor Red
    Write-Log "The file [$file] download failed."
    exit
}

# Check for existing LabTech agent
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    Write-Host "The LabTech agent is already installed." -ForegroundColor Cyan
} elseif (Test-Path $agentPath) {
    Write-Output "The LabTech agent files are present, but the service is not installed."
} else {
    Write-Host "Installing ConnectWise Automate Agent..." -NoNewline
    Start-Process msiexec.exe -Wait -ArgumentList "/I $file /quiet"

    # Wait for the installation to complete
    Start-Sleep -Seconds 45

    # Automate Agent Installation Check
    if (Test-Path $agentPath) {
        Write-Host " done." -ForegroundColor Green
        Write-Log "ConnectWise Automate Agent Installation Completed Successfully!"
        & $config.AutomateSuccess
    } else {
        Write-Host " failed!" -ForegroundColor Red
        Write-Log "ConnectWise Automate Agent installation failed!"
        & $config.AutomateFailure
        Start-Sleep -Seconds 5
        & $config.ClearPath
    }
}


# Set power profile to 'Balanced'
Write-Host "Setting Power Profile..." -NoNewLine
Start-Sleep -Seconds 3
powercfg /S SCHEME_BALANCED
#New-BurntToastNotification -Text "Power profile set to Balanced" -AppLogo "C:\temp\PSNotice\smallA.png"
& $config.PowerProfile
Write-Host " done." -ForegroundColor "Green"
Write-Log "Power profile set to 'Balanced'."
Start-Sleep -Seconds 5


# Disable sleep and hibernation modes
Start-Sleep -Seconds 1
Write-Host "Disabling Sleep and Hibernation..." -NoNewline
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /h off
& $config.HiberSleep
Start-Sleep -Seconds 1
Write-Host " done." -ForegroundColor "Green"
Write-Log "Disabled sleep and hibernation mode."
Start-Sleep -Seconds 2


# Disable fast startup
Start-Sleep -Seconds 1
Write-Host "Disabling Fast Startup..." -NoNewline
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0
Write-Log "Disabled fast startup."
& $config.FastStartup
Start-Sleep -Seconds 1
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 5

# Set power profile
Start-Sleep -Seconds 1
Write-Host "Configuring power profile..." -NoNewline
powercfg /SETACTIVE SCHEME_CURRENT
#New-BurntToastNotification -Text "Power profile set to 'Balanced'" -AppLogo "c:\temp\PSNotice\smallA.png"
& $config.PowerProfile
Start-Sleep -Seconds 1
Write-Host " done." -ForegroundColor "Green"
Write-Log "Power Profile set to 'Balanced'"
Start-Sleep -Seconds 5

# Set power button action to 'Shutdown'
Start-Sleep -Seconds 2
Write-Host "Configuring power button action to shutdown..." -NoNewline
powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /SETACTIVE SCHEME_CURRENT
& $config.PwrButton
Start-Sleep -Seconds 3
Write-Host " done." -ForegroundColor "Green"
Write-Log "Power button action set to 'Shutdown'."
Start-Sleep -Seconds 5

# Set 'lid close action' to do nothing on laptops
Start-Sleep -Seconds 1
if ($deviceType -eq "Laptop") {
    Write-Host "Setting Lid Close Action..." -NoNewline
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /SETACTIVE SCHEME_CURRENT
    Write-Log "'Lid close action' set to Do Nothing. (Laptop)"
    & $config.LidAction
    Start-Sleep -Seconds 2
    Write-Host " done." -ForegroundColor "Green"
    Start-Sleep -Seconds 5
}

# Set the time zone to 'Eastern Standard Time'
Write-Host "Setting EST as default timezone..." -NoNewline
Start-Sleep -Seconds 2
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time"
Write-Log "Time zone set to Eastern Standard Time."
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 3
Write-Host "Syncing clock..." -NoNewline
w32tm /resync -ErrorAction SilentlyContinue | out-null
Start-Sleep -Seconds 2
& $config.timezone
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"    
Start-Sleep -Seconds 5

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
Write-Host "Enabling System Restore..." -NoNewLine
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-Log "System Restore Enabled."
Write-Host " done." -ForegroundColor "Green"
& $config.SystemRestore
Start-Sleep -Seconds 5

# Create restore point
#Write-Host "Creating System Restore Checkpoint..." -nonewline
#Checkpoint-Computer -Description 'Baseline Settings' -RestorePointType 'MODIFY_SETTINGS'
#$restorePoint = Get-ComputerRestorePoint | Sort-Object -Property "CreationTime" -Descending | Select-Object -First 1
#if ($restorePoint -ne $null) {
#    Write-Host " done." -ForegroundColor "Green"
#    Write-Log "Restore Checkpoint Created Successfully."
#} else {
#    Write-Host "Failed to create restore point" -ForegroundColor "Red"
#}
#& $config.Checkpoint
#Start-Sleep -Seconds 5


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
    if ($process -eq $null) {
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

# Check if the system is manufactured by Dell
if ($manufacturer -eq "Dell Inc.") {
    # Set the URL and file path variables
    $SpinnerURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell-Spinner.ps1"
    $SpinnerFile = "c:\temp\Dell-Spinner.ps1"
    $DellSilentURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell_Silent_Uninstall-v2.ps1"
    $DellSilentFile = "c:\temp\Dell_Silent_Uninstall.ps1"
    & $config.DellHardware
    Invoke-WebRequest -Uri $SpinnerURL -OutFile $SpinnerFile -UseBasicParsing -ErrorAction Stop 
    Start-Sleep -seconds 2
    Invoke-WebRequest -Uri $DellSilentURL -OutFile $DellSilentFile -UseBasicParsing -ErrorAction Stop

    if (Test-Path -Path $SpinnerFile) {
    Stop-Transcript *> $null
    & $config.DellBloatware
    & $SpinnerFile
        }
    
} else {
    Write-Warning "Skipping Dell debloat module due to device not meeting hardware requirements."
    #Write-Log "Only Dell systems are eligible for this bloatware removal script."
}
taskkill /f /im procmon64.exe *> $null

Start-Sleep -Seconds 5

Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
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
    if ($process -eq $null) {
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


# Remove Pre-Installed Office
$RemoveOfficeURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office.ps1"
$RemoveOfficeSpinnerURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office-Spinner.ps1"
$RemoveOfficeScript = "c:\temp\Remove-Office.ps1"
$RemoveOfficeSpinner = "c:\temp\Remove-Office-Spinner.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office.ps1" -OutFile "c:\temp\Remove-Office.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office-Spinner.ps1" -OutFile "c:\temp\Remove-Office-Spinner.ps1"
Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
Move-ProcessWindowToTopLeft -processName "procmon64" *> $null
if(Test-Path $RemoveOfficeSpinner) {
    & $config.ScrubOffice
    &$RemoveOfficeSpinner
}
taskkill /f /im procmon64.exe *> $null

Start-Transcript -Append -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt *> $null


# Function to check if the OS is Windows 11
function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

# Check if the OS is Windows 11
if (Is-Windows11) {
    try {
        $Win11DebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $Win11DebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $Win11DebloatFile -DestinationPath 'c:\temp\MITS-Debloat'
        Start-Sleep -Seconds 2
        & $config.Win11
        & 'C:\temp\MITS-Debloat\MITS-Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent
        Write-Log "Windows 11 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Log "This script is intended to run only on Windows 11."
}


# Function to check if the OS is Windows 10
function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

# Trigger MITS Debloat for Windows 10
if (Is-Windows10) {
    try {
        $MITSDebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $MITSDebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $MITSDebloatURL -OutFile $MITSDebloatFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Expand-Archive $MITSDebloatFile -DestinationPath c:\temp\MITS-Debloat -Force
        Start-Sleep -Seconds 2
        & $config.win10
        & 'C:\temp\MITS-Debloat\MITS-Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent
        Write-Log "Windows 10 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Host "This script is intended to run only on Windows 10."
}


# Remove Microsoft OneDrive
try {
    $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
    if ($OneDriveProduct) {
        Write-Host "Removing Microsoft OneDrive (Personal)..." -NoNewline
        $OneDriveProduct | ForEach-Object { $_.Uninstall() } *> $null
        # Recheck if OneDrive is uninstalled
        $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
        if (-not $OneDriveProduct) {
            Write-Host " done." -foregroundColor "Green"
            Write-Log "OneDrive has been successfully removed."
        } else {
            Write-Host "Failed to remove OneDrive." -foregroundColor "Red"
            Write-Log "Failed to remove OneDrive."
        }
    } else {
        Write-Host " "
        Write-Host "OneDrive installation not found." -foregroundColor "Red"
    }
} catch {
    Write-Host "An error occurred: $_" -foregroundColor "Red"
}

# Remove Microsoft Teams Machine-Wide Installer
try {
    $TeamsMWI = Get-Package -Name 'Teams Machine*'
    if ($TeamsMWI) {
        Write-Host "Removing Microsoft Teams Machine-Wide Installer..." -NoNewline
        Get-Package -Name 'Teams Machine*' | Uninstall-Package *> $null
        $MWICheck = Get-Package -Name 'Teams Machine*'
        if (-not $MWICheck) {
            Write-Host " done." -foregroundColor "Green"
            Write-Log "Teams Machine Wide Installer has been successfully uninstalled."
        } else {
            Write-Host "Failed to uninstall Teams Machine Wide Installer." -foregroundColor "Red"
            Write-Log "Failed to uninstall Teams Machine Wide Installer."
        }
    } else {
        Write-Host "Teams Machine Wide Installer not found." -foregroundColor "Red"
    }
} catch {
    Write-Host "An error occurred: $_" -foregroundColor "Red"
}


Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
Move-ProcessWindowToTopLeft -processName "procmon64" *> $null


# Install Google Chrome
$Chrome = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Google Chrome*" }

if ($Chrome) {
    Write-Host "Existing Google Chrome installation found." -ForegroundColor "Cyan"
} else {
    $FilePath = "c:\temp\ChromeSetup.exe"
    if (-not (Test-Path $FilePath)) {
        $ProgressPreference = 'Continue'
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ChromeSetup.exe"
        Invoke-WebRequest -OutFile c:\temp\ChromeSetup.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ChromeSetup.exe" -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 1373744 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        & $config.chromeNotification
        Write-Host "Installing Google Chrome..." -NoNewline
        Start-Process -FilePath "C:\temp\Chromesetup.exe" -ArgumentList "/silent /install" -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Google Chrome successfully installed."
        & $config.chromeComplete
        Start-Sleep -Seconds 15
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
    else {
        # Report download error
        & $config.chromeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Google Chrome download failed!"
        Start-Sleep -Seconds 10
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}

# Acrobat Installation
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" }
if ($Acrobat) {
    Write-Host "Existing Acrobat Reader installation found." -ForegroundColor "Cyan"
} else {
    $FilePath = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    if (-not (Test-Path $FilePath)) {
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRdrDC2300620360_en_US.exe"
        Write-Host "Downloading Adobe Acrobat Reader (277,900,248 bytes)..." -NoNewline
        & $config.acrobatDownload
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
        & $config.ClearPath   
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 277900248 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Host "Installing Adobe Acrobat Reader..." -NoNewline
        & $config.acrobatNotification
        Start-Process -FilePath $FilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -Wait
        & $config.acrobatComplete
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Adobe Acrobat installed successfully."
        Start-Sleep -Seconds 2
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Download failed. File size does not match."
        & $config.acrobatFailure
        Start-Sleep -Seconds 5
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}


# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    Write-Host "Existing Microsoft Office installation found." -ForegroundColor "Yellow"
} else {
    $FilePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $FilePath)) {
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Invoke-WebRequest -OutFile c:\temp\OfficeSetup.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe" -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        & $config.officeNotice
        Write-Host "Installing Office 365..." -NoNewline
        Start-Process -FilePath "C:\temp\Officesetup.exe" -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Office 365 Installation Completed Successfully."
        Start-Sleep -Seconds 10
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
    else {
        # Report download error
        & $config.officeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Office download failed!"
        Start-Sleep -Seconds 10
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}


# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }

if ($SWNE) {
    Write-Host "Existing NetExtender installation found." -ForegroundColor "Cyan"
} else {
    $NEFilePath = "c:\temp\NXSetupU-x64-10.2.337.exe"
    if (-not (Test-Path $NEFilePath)) {
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe"
        Invoke-WebRequest -OutFile c:\temp\NXSetupU-x64-10.2.337.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe" -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $NEFilePath).Length
    $ExpectedSize = 4788816 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        Write-Host "Installing Sonicwall NetExtender..." -NoNewline
        start-process -filepath "C:\temp\NXSetupU-x64-10.2.337.exe" /S -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Sonicwall NetExtender installation completed successfully."
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
    }
    else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Sonicwall NetExtender download failed!"
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
    }
}

# Stop Procmon
taskkill /f /im procmon64.exe *> $null

Write-Output " "
Write-Host "Starting Bitlocker Configuration..."
Write-Output " "

# Check if TPM module is enabled
$TPM = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled().Isenabled -eq 'True'} -ErrorAction SilentlyContinue

# Check if Windows version and BitLocker-ready drive are present
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {

    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Create the recovery key
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null

    # Add TPM key
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector | Out-Null
    Start-Sleep -Seconds 15 # Wait for the protectors to take effect

    # Enable Encryption
    Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -em aes256" -Verb runas -Wait *> $null

    # Get Recovery Key GUID
    $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorID

    # Backup the Recovery to AD
    manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID *> $null
    manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"

    # Retrieve and Output the Recovery Key Password
    $RecoveryKeyPW = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty RecoveryPassword
    Write-Log "Bitlocker Recovery Key Password: $RecoveryKeyPW"
}

# Enable and start Windows Update Service
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv
Start-Sleep -Seconds 3
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running' -and $service.StartType -eq 'Manual') {
    Write-Host "The Windows Update service has been successfully enabled and is running."
} else {
    Write-Host "Failed to start and/or enable the Windows Update service."
}


# Installing Windows Updates
& $config.UpdateNotice
Start-Service -Name wuauserv *> $null
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/update_windows.ps1" -OutFile "c:\temp\update_windows.ps1"
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows.ps1"
    Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath
    Start-Sleep -seconds 2
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
} else {
    Write-host "Windows update execution failed!" -ForegroundColor Red
}


# Notify device Baseline is complete and ready to join domain.
$NTFY2 = "& cmd.exe /c curl -d '%ComputerName% Baseline is complete & ready for domain join!' 172-233-196-225.ip.linodeusercontent.com/sslvpn"
Invoke-Expression -command $NTFY2 *> $null


Write-Output " "
Write-Output "Starting Domain/Azure AD Join Function..."
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
Write-Output " "
# Prompt the user to connect to SSL VPN
$choice = Read-Host -Prompt "Do you want to connect to SSL VPN? Enter Y or N"

if ($choice -eq "Y" -or $choice -eq "N") {
    if ($choice -eq "Y") {
                
        if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
            Write-Output 'NetExtender detected successfully, starting connection...'
            start C:\temp\ssl-vpn.bat
            Start-Sleep -Seconds 3
            Read-Host -Prompt "Press Enter once connected to SSL VPN to continue."
        } else {
            Write-Output " "
            Write-Output 'NetExtender not found! Exiting Script...'
            break
        }
    } else {
        # Skip the VPN connection setup
        Write-Output " "
        Write-Output "Skipping VPN Connection Setup..."
        Write-Output " "
    }
} else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter Y or N."
    Write-Log "Invalid response received."
    break
}

# Prompt the user to choose between standard domain join or Azure AD join
$choice = Read-Host -Prompt "Do you want to perform a standard domain join (S) or join Azure AD (A)? Enter S or A"

# Validate the user input
if ($choice -eq "A" -or $choice -eq "S") {

    # Perform the join operation based on the user choice
    if ($choice -eq "S") {
        # Get the domain name from the user
        $cred = Get-Credential -Message "Enter the credentials for the domain join operation"
        $domain = Read-Host -Prompt "Enter the domain name to join"

        # Join the system to the domain using the credentials
        $joinOutput = Add-Computer -DomainName $domain -Credential $cred 
        $domainJoinSuccessful = Test-ComputerSecureChannel
        # Check if the output contains the warning message
        if ($joinOutput -notlike "*Warning: The changes will take effect after you restart the computer*") {
            Write-Host " "
            Write-Host "Domain join completed successfully." -ForegroundColor Green
            Write-Log "$env:COMPUTERNAME joined to $domain successfully"
        } else {
            Write-Host " "
            Write-Host "Domain join completed but requires a restart." -ForegroundColor Yellow
            Write-Log "$env:COMPUTERNAME joined to $domain but requires a restart."
        }
    } else {
        # Join the system to Azure AD using Work or school account
        Write-Output "Starting Azure AD Join using Work or school account..."
        Start-Sleep -Seconds 2
        Start-Process "ms-settings:workplace"
        # Run dsregcmd /status and capture its output
        $output = dsregcmd /status | Out-String

        # Extract the AzureAdJoined value
        $azureAdJoined = $output -match 'AzureAdJoined\s+:\s+(YES|NO)' | Out-Null
        $azureAdJoinedValue = if($matches) { $matches[1] } else { "Not Found" }

        # Display the extracted value
        Write-Host " "
        Write-Host "AzureAdJoined: $azureAdJoinedValue"
        Write-Log "$env:COMPUTERNAME joined to Azure AD."
    }
} else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter A or S."
    Write-Log "Invalid domain join response received."
    #break
}


# Final log entry
& $config.baselineComplete
Write-Log "Baseline configuration completed successfully."
Write-Host " "
Stop-Transcript  
Start-Sleep -seconds 1
Start-Process "appwiz.cpl"
Write-Host " "
Write-Host " "
Read-Host -Prompt "Press Enter to exit."
