Set-Executionpolicy RemoteSigned -Force *> $null
Clear-Host
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'

# Central Configuration
$config = @{
    AcrobatComplete      = "c:\temp\psnotice\appnotice\acrobat\AcrobatComplete.ps1"
    AcrobatFailure       = "C:\temp\psnotice\appnotice\acrobat\failure\New-ToastNotification.ps1"
    AcrobatInstaller     = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    AutomateFailure      = "C:\temp\psnotice\AppNotice\automate\failure\New-ToastNotification.ps1"
    AutomateSuccess      = "C:\temp\psnotice\AppNotice\automate\"
    BaselineComplete     = "C:\temp\psnotice\BaselineComplete\New-ToastNotification.ps1"
    Checkpoint           = "C:\temp\psnotice\checkpoint\New-ToastNotification.ps1"
    ChromeDownload       = "C:\temp\psnotice\AppNotice\Chrome\download\New-ToastNotification.ps1"
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
    NEGui                = "C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NEGui.exe"
    NoSnooze             = "c:\temp\nosnooze.ps1"
    NoSnoozeUrl          = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NoSnooze.zip"
    NoSnoozeZip          = "c:\temp\nosnooze.zip"
    OfficeComplete       = "C:\temp\psnotice\OfficeNotice\complete\New-ToastNotification.ps1"
    OfficeFailure        = "C:\temp\psnotice\OfficeNotice\failure\New-ToastNotification.ps1"
    OfficeInstaller      = "c:\temp\Office2016_ProPlus"
    PowerProfile         = "C:\temp\psnotice\powerprofile\New-ToastNotification.ps1"
    PSNoticeFile         = "c:\temp\psnotice.zip"
    PSNoticePath         = "c:\temp\PSNotice"
    ProcmonURL           = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Procmon.exe"
    ProcmonFile          = "c:\temp\Procmon.exe"
    PSNoticeUrl          = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/psnotice.zip"
    RemoveOfficeURL      = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office.ps1"
    RemoveOfficeSpinURL  = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office-Spinner.ps1"
    RemoveOfficeScript   = "c:\temp\Remove-Office.ps1"
    RemoveOfficeSpinner  = "c:\temp\Remove-Office-Spinner.ps1"
    ScrubOffice          = "C:\temp\psnotice\scruboffice\New-ToastNotification.ps1"
    SendWKey             = "C:\temp\sendwkey.exe"
    SendWurl             = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/SendWKey.exe"
    StartBaseline        = "C:\temp\psnotice\BaselineStart\New-ToastNotification.ps1"
    SystemRestore        = "C:\temp\psnotice\SystemRestore\New-ToastNotification.ps1"
    TempFolder           = "C:\temp"
    TimeZone             = "C:\temp\psnotice\TimeZone\New-ToastNotification.ps1"
    UpdateComplete       = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    UpdateNotice         = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    Win10                = "C:\temp\psnotice\win10\New-ToastNotification.ps1"
    Win11                = "C:\temp\psnotice\win11\New-ToastNotification.ps1"
}


# Set console formatting
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline;
    Write-Host -ForegroundColor $Color $Message;
}

# Print Script Title
#################################
$Padding = ("=" * [System.Console]::BufferWidth);
Write-Host -ForegroundColor "Red" $Padding -NoNewline;
Print-Middle "MITS - New Workstation Baseline Utility";
Write-Host -ForegroundColor DarkRed "                                                      version 9.7";
Write-Host -ForegroundColor "Red" -NoNewline $Padding;
Write-Host " "
Set-ExecutionPolicy -Scope process RemoteSigned -Force


# Create temp directory and baseline log
function Initialize-Environment {
    if (-not (Test-Path $config.TempFolder)) {
        New-Item -Path $config.TempFolder -ItemType Directory | Out-Null
    }
    if (-not (Test-Path $config.LogFile)) {
        New-Item -Path $config.LogFile -ItemType File | Out-Null
    }
}


# Baseline Operatoins Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $config.LogFile -Value "$(Get-Date) - $Message"
}


# Start baseline transcript log
Start-Transcript -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt


# Start Baseline
[Console]::ForegroundColor = [System.ConsoleColor]::Yellow
[Console]::Write("`n")
[Console]::Write("`n")
$Baseline = "Starting workstation baseline..."
foreach ($Char in $Baseline.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
[Console]::Write(" ")
[Console]::ResetColor() 
[Console]::WriteLine()
[Console]::Write("`n")
Start-Sleep -Seconds 2

# Start baseline log file
Write-Log "Automated workstation baseline has started"

# Device Identification
# PCSystemType values: 1 = Desktop, 2 = Mobile, 3 = Workstation, 4 = Enterprise Server, 5 = SOHO Server, 6 = Appliance PC, 7 = Performance Server, 8 = Maximum
$computerSystem = Get-WmiObject Win32_ComputerSystem
$manufacturer = $computerSystem.Manufacturer
if ($computerSystem.PCSystemType -eq 2) {
    Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
} else {
    #Write-Host "This is a Desktop or other non-laptop system. Continuing with the next part of the script."
}

# Start Baseline Notification
#& $config.StartBaseline | Out-Null


$ModChk = "Installing required powershell modules..."

foreach ($Char in $ModChk.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}

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
    
}
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 


# Stage Procmon
$Notice = "Staging Procmon..."
foreach ($Char in $Notice.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}

# Download Procmon from LabTech server
Invoke-WebRequest -Uri $config.ProcmonURL -OutFile $config.ProcmonFile *> $null

if (Test-Path $config.ProcmonFile)
{
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    Start-Sleep -Seconds 2
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" failed.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    Start-Sleep -Seconds 2
}


# Stage Toast Notifications
$Notice = "Staging notifications..."
foreach ($Char in $Notice.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}

#$ProgressPreference = 'Continue'
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
$url = $config.SendWurl
$filePath = $config.TempFolder
# Check if the OS is Windows 11 before running code block
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
if ($osVersion -gt "10.0.22000*") {
    # The code that should only run on Windows 11
    $Snooze = "Disabling notification snooze..."
    foreach ($Char in $Snooze.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    Add-Type -AssemblyName System.Windows.Forms
    Start-Sleep -Seconds 5
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -uri $url -OutFile $config.SendWKey
    $ProgressPreference = 'Continue'
    # Define the arguments for SendWKey.exe
    $arguments = '#{n}'
    # Execute SendWKey.exe with arguments
    Start-Process -FilePath $config.SendWKey -ArgumentList $arguments -NoNewWindow -Wait
    Start-Sleep -Seconds 2
    # Send Space keystroke
    [System.Windows.Forms.SendKeys]::SendWait(' ')
    [System.Windows.Forms.SendKeys]::SendWait('{ESC}')
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor() 
    [Console]::WriteLine()
} else {
    Write-Host "Disable notification snooze function is only applicable to Windows 11 OS."
}

# Stop & disable the Windows Update service
$WU = "Suspending Windows Update..."
foreach ($Char in $WU.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}

Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled
Start-Sleep -Seconds 3
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()  
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()  
}

# Disable Offline File Sync
# Set the path of the Offline Files registry key
$registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

# Check if the registry path exists, if not, create it
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force *> $null
}


# Disable Offline File Sync
$OfflineFiles = "Disabling Offline File Sync..."
foreach ($Char in $OfflineFiles.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 *> $null
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 


# Set power profile to 'Balanced'
$Pwr = "Setting 'Balanced' Power Profile..."
foreach ($Char in $Pwr.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
Start-Sleep -Seconds 2
powercfg /S SCHEME_BALANCED *> $null
#& $config.PowerProfile
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Write-Log "Power profile set to 'Balanced'."
Start-Sleep -Seconds 5


# Disable sleep and hibernation modes
Start-Sleep -Seconds 1
$HibSlp = "Disabling Sleep & Hibernation..."
foreach ($Char in $HibSlp.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
powercfg /change standby-timeout-ac 0 *> $null
powercfg /change hibernate-timeout-ac 0 *> $null
powercfg /h off *> $null
& $config.HiberSleep
Start-Sleep -Seconds 2
Write-Log "Disabled sleep and hibernation mode."
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 2


# Disable fast startup
Start-Sleep -Seconds 2
$FStart = "Disabling Fast Startup...."
foreach ($Char in $FStart.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0
Write-Log "Disabled fast startup."
& $config.FastStartup
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 5


# Set power button action to 'Shutdown'
Start-Sleep -Seconds 2
$PwrBtn = "Configuring 'Shutdown' power button action..."
foreach ($Char in $PwrBtn.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /SETACTIVE SCHEME_CURRENT
& $config.PwrButton
Start-Sleep -Seconds 2
Write-Log "Power button action set to 'Shutdown'."
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 5

# Set 'lid close action' to do nothing on laptops
Start-Sleep -Seconds 1
if ($deviceType -eq "Laptop") {
    $Lid = "Setting 'Do Nothing' lid close action..."
    foreach ($Char in $Lid.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /SETACTIVE SCHEME_CURRENT
    Write-Log "'Lid close action' set to Do Nothing. (Laptop)"
    & $config.LidAction
    Start-Sleep -Seconds 2
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    Start-Sleep -Seconds 5
}

# Set the time zone to 'Eastern Standard Time'
$EST = "Setting EST as default timezone..."
foreach ($Char in $EST.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
Start-Sleep -Seconds 2
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time"
Write-Log "Time zone set to Eastern Standard Time."
Start-Sleep -Seconds 2
& $config.timezone
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 

Start-Sleep -Seconds 3
$Sync = "Syncing system clock..."
foreach ($Char in $Sync.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
w32tm /resync -ErrorAction SilentlyContinue | out-null
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()    
Start-Sleep -Seconds 5

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
$Restore = "Enabling System Restore..."
foreach ($Char in $Restore.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-Log "System Restore Enabled."
& $config.SystemRestore
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()    
Start-Sleep -Seconds 5

# Create restore point
#[Console]::Write("Creating System Restore Checkpoint...")
#Checkpoint-Computer -Description 'Baseline Settings' -RestorePointType 'MODIFY_SETTINGS'
#$restorePoint = Get-ComputerRestorePoint | Sort-Object -Property "CreationTime" -Descending | Select-Object -First 1
#if ($restorePoint -ne $null) {
# [Console]::ForegroundColor = [System.ConsoleColor]::Green
#[Console]::Write(" done.")
#[Console]::ResetColor()
#[Console]::WriteLine()   
#Write-Log "Restore Checkpoint Created Successfully."
#} else {
#}[Console]::ForegroundColor = [System.ConsoleColor]::Red
#[Console]::Write(" failed.")
#[Console]::ResetColor()
#[Console]::WriteLine()    
#& $config.Checkpoint
#Start-Sleep -Seconds 5

# Offline Files Function to check if the OS is Windows 10
function Test-Win10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

# Disable Offline Files on Windows 10
if (Test-Win10) {
    try {
        # Set the path of the Offline Files registry key
        $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"
    # Check if the registry path exists, if not, create it
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }
    # Set the value to disable Offline Files
    Set-ItemProperty -Path $registryPath -Name "Start" -Value 4
    # Output the result
    Write-Host "Offline Files has been disabled on Windows 10. A system restart may be required for changes to take effect."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Host "This script is intended to run only on Windows 10."
}

function Test-Win11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption

    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

# Disable Offline Files on Windows 11
if (Test-Win11) {
    try {
    # Set the path of the Offline Files registry key
    $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

    # Check if the registry path exists, if not, create it
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }

    # Set the value to disable Offline Files
    Set-ItemProperty -Path $registryPath -Name "Start" -Value 4

    # Output the result
    Write-Host "Offline Files has been disabled on Windows 10. A system restart may be required for changes to take effect."

    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Host "This script is intended to run only on Windows 11."
}


# Check if the system is manufactured by Dell
if ($manufacturer -eq "Dell Inc.") {
    Stop-Transcript *> $null
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
    & $config.DellBloatware
    & $SpinnerFile
        }

} else {
    Write-Warning "Skipping Dell debloat module due to device not meeting hardware requirements."
    Write-Log "Skipping Dell debloat module due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}

# Kill procmon 
taskkill /f /im procmon* *> $null


# Registry Check
$OfficeUninstallStrings = (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Microsoft 365 - *"} | Select-Object -ExpandProperty UninstallString)
if ($null -ne $OfficeUninstallStrings) {
    $RPIO = "Removing Pre-Installed Office 365 Applications..."
    foreach ($Char in $RPIO.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    [Console]::ResetColor()
    [Console]::WriteLine()    
    Invoke-WebRequest -Uri $config.RemoveOfficeURL -OutFile $config.RemoveOfficeScript
    Start-Sleep -seconds 2
    Invoke-WebRequest -Uri $config.RemoveOfficeSpinURL -OutFile $config.RemoveOfficeSpinner
    if (Test-Path -Path $config.RemoveOfficeSpinner) {
        & $config.ScrubOffice
        & $RemoveOfficeSpinner
        }
} else {
    Write-Warning "Skipping Pre-Installed Office Removal module due to not meeting application requirements."
    Write-Log "Skipping Pre-Installed Office Removal module due to not meeting application requirements."
    Start-Sleep -Seconds 1
}

# Restart transcript
Start-Transcript -Append -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt *> $null


# Check Bitlocker Compatibility
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {

    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    $SBLC = "Configuring Bitlocker disk encryption..."
    foreach ($Char in $SBLC.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
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
    Write-Log "Bitlocker Recovery Key: $RecoveryKeyPW"
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    
} else {
    Write-Warning "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}


# ConnectWise Automate Agent Installation
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"

# Check for existing LabTech agent
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    #[Console]::Write("ConnectWise Automate agent is already installed.")
    $LTInstalled = "ConnectWise Automate agent is already installed."
    Start-Sleep -Seconds 1
    foreach ($Char in $LTInstalled.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    [Console]::ResetColor()
    [Console]::WriteLine()
} elseif (Test-Path $agentPath) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    #[Console]::Write("ConnectWise Automate agent files are present, but the service is not installed")
    $Broken = "ConnectWise Automate agent files are present, but the service is not installed."
    foreach ($Char in $Broken.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    [Console]::ResetColor() 
    [Console]::WriteLine() 
} else {
    #[Console]::WriteLine("Downloading Connectwise Automate Agent...")
    $CWDL = "Downloading ConnectWise Automate Agent..."
    foreach ($Char in $CWDL.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    Invoke-WebRequest -Uri $installerUri -OutFile $file -ErrorAction SilentlyContinue
    # Verify dowload
    if (Test-Path $file) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.`n")
    [Console]::ResetColor()    
    #[Console]::WriteLine("`n")
    $LTIns = "Installing ConnectWise Automate Agent..."
    foreach ($Char in $LTIns.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    Start-Process msiexec.exe -Wait -ArgumentList "/I $file /quiet"
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    } else {
        Write-Log "The file [$file] download failed."
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" failed.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
        exit
}
    # Wait for the installation to complete
    Start-Sleep -Seconds 45

    # Automate Agent Installation Check
    if (Test-Path $agentPath) {
        Write-Log "ConnectWise Automate Agent Installation Completed Successfully!"
        & $config.AutomateSuccess
    } else {
        Write-Log "ConnectWise Automate Agent installation failed!"
        & $config.AutomateFailure
    }
}


# Launch Procmon
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

Start-Sleep -Seconds 2

# Install Google Chrome
$Chrome = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Google Chrome*" }

if ($Chrome) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    $FoundChrome = "Existing Google Chrome installation found."
    foreach ($Char in $FoundChrome.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    [Console]::ResetColor()
    [Console]::WriteLine()  
} else {
    $ChromePath = "c:\temp\ChromeSetup.exe"
    if (-not (Test-Path $ChromePath)) {
        $ProgressPreference = 'Continue'
        $ChromeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ChromeSetup.exe"
        $CWDL = "Downloading Google Chrome..."
    foreach ($Char in $CWDL.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }   
        & $config.ChromeDownload
        Invoke-WebRequest -OutFile $ChromePath -Uri $ChromeURL -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.`n")
        [Console]::ResetColor() 
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $ChromePath).Length
    $ExpectedSize = 1373744 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        & $config.chromeNotification
        $IGC = "Installing Google Chrome..."
        foreach ($Char in $IGC.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        Start-Process -FilePath $ChromePath -ArgumentList "/silent /install" -Wait
        Write-Log "Google Chrome installed successfully."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
        & $config.chromeComplete
        Start-Sleep -Seconds 10
        Remove-Item -Path $ChromePath -force -ErrorAction SilentlyContinue
    }
    else {
        # Report download error
        & $config.chromeFailure
        Write-Log "Google Chrome download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        $GCDE = "Download failed! file not found or size does not match"
        foreach ($Char in $GCDE.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        [Console]::ResetColor()
        [Console]::WriteLine() 
        Start-Sleep -Seconds 10
        Remove-Item -Path $ChromePath -force -ErrorAction SilentlyContinue
    }
}


# Acrobat Installation
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" }
if ($Acrobat) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    $EAAIF = "Existing Acrobat Reader installation found."
    foreach ($Char in $EAAIF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
    [Console]::ResetColor()
    [Console]::WriteLine()  
} else {
    #$AcroFilePath = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    $AcroFilePath = "c:\temp\AcroRead.exe"
    if (-not (Test-Path $AcroFilePath)) {
        #$URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRdrDC2300620360_en_US.exe"
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRead.exe"
        #$DLAAR = "Downloading Adove Acrobat Reader (277,900,248 bytes...)"
        $DLAAR = "Downloading Adove Acrobat Reader..."
        foreach ($Char in $DLAAR.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        & $config.acrobatDownload
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        & $config.ClearPath
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()       
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1452648 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        $IAAR = "Installing Adobe Acrobat Reader..."
        foreach ($Char in $IAAR.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        & $config.acrobatNotification
        $process = Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -wait
        Start-Sleep -Seconds 5

    # Minimize the Acrobat installer window
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WindowHandler {
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    public static void MinimizeWindow(IntPtr hWnd) {
    ShowWindowAsync(hWnd, 2); // 2 corresponds to SW_MINIMIZE
        }
    }
"@

# Find the window handle and minimize
if ($process -and $process.MainWindowHandle -ne [IntPtr]::Zero) {
    [WindowHandler]::MinimizeWindow($process.MainWindowHandle)
}
        & $config.acrobatComplete
        Write-Log "Adobe Acrobat installed successfully."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.`n")
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 2
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        # Report download error
        Write-Log "Download failed. File size does not match."
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        $AARDE = "Download failed or file size does not match."
        foreach ($Char in $AARDE.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        [Console]::ResetColor()
        [Console]::WriteLine()    
        & $config.acrobatFailure
        Start-Sleep -Seconds 5
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}


# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    $EMOIF = "Existing Microsoft Office installation found."
    foreach ($Char in $EMOIF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
    [Console]::ResetColor()
    [Console]::WriteLine()
    goto NE_Install    
} else {
    $OfficePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $OfficePath)) {
        $OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Invoke-WebRequest -OutFile $OfficePath -Uri $OfficeURL -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        & $config.officeNotice
        $IO365 = "Installing Microsoft Office 365..."
        foreach ($Char in $IO365.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        Start-Process -FilePath $OfficePath -Wait
        if (!(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"})) {
            Write-Log "Office 365 Installation Completed Successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()  
            Start-Sleep -Seconds 10
            Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
            } else {
            $MO365IF = "Microsoft Office 365 installation failed."
            foreach ($Char in $MO365IF.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
            }
        
    }
    else {
        # Report download error
        & $config.officeFailure
        Write-Log "Office download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        $O365DLF = "Download failed or file size does not match"
        foreach ($Char in $O365DLF.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 10
        Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
    }
}

# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }

if ($SWNE) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    $ENEIF = "Existing NetExtender installation found."
    foreach ($Char in $ENEIF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
    [Console]::ResetColor()
    [Console]::WriteLine()    
} else {
    $NEFilePath = "c:\temp\NXSetupU-x64-10.2.337.exe"
    if (-not (Test-Path $NEFilePath)) {
        $NEURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe"
        Invoke-WebRequest -OutFile $NEFilePath -Uri $NEURL -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $NEFilePath).Length
    $ExpectedSize = 4788816 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        [Console]::Write("Installing Sonicwall NetExtender...")
        start-process -filepath $NEFilePath /S -Wait
        if (Test-Path $config.NEGui) {
            Write-Log "Sonicwall NetExtender installation completed successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()
            Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
        }
    } else {
        # Report download error
        Write-Log "Sonicwall NetExtender download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write("Download failed! File does not exist or size does not match.")
        $NEDF = "Download failed! File does not exist or size does not match"
        foreach ($Char in $NEDF.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        [Console]::ResetColor()
        [Console]::WriteLine()    
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
    }
}

# Remove Microsoft OneDrive
try {
    $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
    if ($OneDriveProduct) {
        $ROD = "Removing Microsoft OneDrive (Personal)..."
        foreach ($Char in $ROD.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }

        $OneDriveProduct | ForEach-Object { $_.Uninstall() } *> $null
        # Recheck if OneDrive is uninstalled
        $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
        if (-not $OneDriveProduct) {
            Write-Log "OneDrive has been successfully removed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()    
        } else {
            Write-Log "Failed to remove OneDrive."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            $FROD = " Failed to remove OneDrive"
            foreach ($Char in $FROD.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
            [Console]::ResetColor()
            [Console]::WriteLine()    
        }
    } else {
        #[Console]::Write("`n")
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        $ODINF = "OneDrive installation not found."
        foreach ($Char in $ODINF.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
            [Console]::ResetColor()
            [Console]::WriteLine()
    }
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    $ODE = "An error occurred: $_"
    foreach ($Char in $ODE.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
    [Console]::ResetColor()
    [Console]::WriteLine()
}


# Remove Microsoft Teams Machine-Wide Installer
try {
    $TeamsMWI = Get-Package -Name 'Teams Machine*'
    if ($TeamsMWI) {
        $RTMWI = "Removing Microsoft Teams Machine-Wide Installer..."
        foreach ($Char in $RTMWI.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
        }
        [Console]::ResetColor()
        [Console]::WriteLine()
        Get-Package -Name 'Teams Machine*' | Uninstall-Package *> $null
        $MWICheck = Get-Package -Name 'Teams Machine*'
        if (-not $MWICheck) {
            Write-Log "Teams Machine Wide Installer has been successfully uninstalled."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()   
        } else {
            Write-Log "Failed to uninstall Teams Machine Wide Installer."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            $FTMWU = "Failed to uninstall Teams machine wide installer."
            foreach ($Char in $FTMWU.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
            [Console]::ResetColor()
            [Console]::WriteLine()
        }
    } else {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        #[Console]::Write("`n")
        $TMWINF = "Teams machine wide installation not found."
        foreach ($Char in $TMWINF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
        [Console]::ResetColor()
        [Console]::WriteLine()    
    }
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    $RTMWIE = "An error occurred: $_"
    foreach ($Char in $RTMWI.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
}


# Stop Procmon
taskkill /f /im procmon64.exe *> $null


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
Write-Output " "
# Enable and start Windows Update Service
$EWUS = "`bEnabling Windows Update Service..."
foreach ($Char in $EWUS.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv
Start-Sleep -Seconds 3
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running' -and $service.StartType -eq 'Manual') {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
}


# Installing Windows Updates
& $config.UpdateNotice
$IWU = "Checking for Windows Updates..."
foreach ($Char in $IWU.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30
}
   
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wju10755/Baseline/main/Update_Windows-v2.ps1" -OutFile "c:\temp\update_windows.ps1"
$ProgressPreference = 'Continue'
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows.ps1"
    Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath
    Start-Sleep -seconds 3
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()  
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    $WUEF = "Windows Update execution failed!"
    foreach ($Char in $WUEF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
        [Console]::ResetColor()
        [Console]::WriteLine()  
}

# Notify device Baseline is complete and ready to join domain.
$NTFY2 = "& cmd.exe /c curl -d '%ComputerName% Baseline is complete & ready to join the domain!' 172-233-196-225.ip.linodeusercontent.com/sslvpn"
Invoke-Expression -command $NTFY2 *> $null


Write-Output " "
[Console]::Write("`b`bStarting Domain/Azure AD Join Function...`n")
Write-Output " "
Start-Sleep -Seconds 1
#$SDJF = "Starting Domain/Azure AD Join Function..."
#foreach ($Char in $SDJF.ToCharArray()) {
#    [Console]::Write("$Char")
#    Start-Sleep -Milliseconds 30    
#    }

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
$ProgressPreference = 'Continue'
# Prompt the user to connect to SSL VPN
$SDJF = "Do you want to connect to SSL VPN? Enter Y or N?`n"
foreach ($Char in $SDJF.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }
$choice = Read-Host

if ($choice -eq "Y" -or $choice -eq "N") {
    if ($choice -eq "Y") {
                
        if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
            [Console]::Write("NetExtender detected successfully, starting connection...")
            start C:\temp\ssl-vpn.bat
            Start-Sleep -Seconds 3
            Read-Host -Prompt "Press Enter once connected to SSL VPN to continue."
        } else {
            [Console]::Write("`n")
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            $NENF = "SonicWall NetExtender not found"
            foreach ($Char in $NENF.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
            [Console]::ResetColor()
            [Console]::WriteLine()   
            goto continue_script
        }
    } else {
        # Skip the VPN connection setup
        #[Console]::Write("`n")
        $SVPNS = "Skipping VPN Connection Setup..."
        foreach ($Char in $SVPNS.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
            [Console]::ResetColor()
            [Console]::WriteLine()
            #[Console]::Write("`n")

    }
} else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter Y or N."
    Write-Log "Invalid response received."
    goto continue_script
}

:continue_script
# Prompt the user to choose between standard domain join or Azure AD join
[Console]::Write("`n")
$JoinOp = "Do you want to perform a standard domain join (S) or join Azure AD (A)? Enter S or A?`n"
foreach ($Char in $JoinOp.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }

$choice = Read-Host

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
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            $DJCS = "Domain join operation completed successfully."
            foreach ($Char in $DJCS.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
                [Console]::ResetColor()
                [Console]::WriteLine()
            Write-Log "$env:COMPUTERNAME joined to $domain successfully"
        } else {
            Write-Host " "
            [Console]::ForegroundColor = [System.ConsoleColor]::Yellow
            $DJCSRR = "Domain join operation completed successfully, restart is required!"
            foreach ($Char in $DJCSRR.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
                [Console]::ResetColor()
                [Console]::WriteLine()
            Write-Log "$env:COMPUTERNAME joined to $domain but requires a restart."
        }
    } else {
        # Join the system to Azure AD using Work or school account
        $SAADJ = "Starting Azure AD Join operation using Work or School account..."
        foreach ($Char in $SAADJ.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        Start-Sleep -Seconds 2
        Start-Process "ms-settings:workplace"
        # Run dsregcmd /status and capture its output
        $output = dsregcmd /status | Out-String

        # Extract the AzureAdJoined value
        $azureAdJoined = $output -match 'AzureAdJoined\s+:\s+(YES|NO)' | Out-Null
        $azureAdJoinedValue = if($matches) { $matches[1] } else { "Not Found" }

        # Display the extracted value
        Write-Host " "
        $AADJV = "AzureADJoined: $azureADJoinedValue"
        foreach ($Char in $AADJV.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
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
$BCCS = "Baseline configuration completed successfully!"
foreach ($Char in $BCCS.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }
    [Console]::ResetColor()
    [Console]::WriteLine()
Write-Host " "
Stop-Transcript  
Start-Sleep -seconds 1
Start-Process "appwiz.cpl"
Write-Host " "
Write-Host " "
Read-Host -Prompt "Press Enter to exit"
