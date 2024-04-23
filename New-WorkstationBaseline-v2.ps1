Set-Executionpolicy RemoteSigned -Force *> $null
Clear-Host
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'

# Central Configuration
$config = @{
    AcrobatInstaller     = "c:\temp\AcroRead.exe"
    ChromeInstaller      = "c:\temp\ChromeSetup.exe"
    DebloatSpinner       = "C:\temp\Win11Debloat_Spinner.ps1"
    LogFile              = "C:\temp\baseline.log"
    NEGui                = "C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NEGui.exe"
    OfficeInstaller      = "c:\temp\Office2016_ProPlus"
    ProcmonURL           = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Procmon.exe"
    ProcmonFile          = "c:\temp\Procmon.exe"
    RemoveOfficeURL      = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office.ps1"
    RemoveOfficeSpinURL  = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-Office-Spinner.ps1"
    RemoveOfficeScript   = "c:\temp\Remove-Office.ps1"
    RemoveOfficeSpinner  = "c:\temp\Remove-Office-Spinner.ps1"
    RemoveOneNoteURL     = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-OneNote.ps1"
    RemoveOneNoteFile    = "C:\temp\Remove-OneNote.ps1"
    RemoveOneNoteSpinURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Remove-OneNote-Spinner.ps1"
    RemoveOneNoteSpinner = "C:\temp\Remove-OneNote-Spinner.ps1"
    SendWKey             = "C:\temp\sendwkey.exe"
    SendWurl             = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/SendWKey.exe"
    TempFolder           = "C:\temp"
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
Print-Middle "MITS - New Workstation Baseline Script";
Write-Host -ForegroundColor Cyan "                                                   version 10.3.2";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "


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


Function Remove-M365([String]$appName)
{
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like $appName} | Select UninstallString)
    if($uninstall -ne $null){
        Write-Host "Removing $appName..."
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
    }
    else{
        Write-Host "$appName is not installed."
    }
}


# Function to write text with delay
function Write-Delayed {
    param([string]$Text, [switch]$NewLine = $true)
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
}

# Start Baseline
[Console]::ForegroundColor = [System.ConsoleColor]::Yellow
[Console]::Write("`n")
Write-Delayed "Starting workstation baseline..."
[Console]::Write(" ")
[Console]::ResetColor() 
[Console]::WriteLine()
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
# Device Identification
# PCSystemType values: 1 = Desktop, 2 = Mobile, 3 = Workstation, 4 = Enterprise Server, 5 = SOHO Server, 6 = Appliance PC, 7 = Performance Server, 8 = Maximum
$flagFilePath = "C:\Temp\WakeLock.flag"
# Get computer system information using CIM (more efficient and modern compared to WMI)
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType
    $manufacturer = $computerSystem.Manufacturer

    # Check if the system is a mobile device
    if ($pcSystemType -eq 2) {
        # Mobile device detected, launching presentation settings
        Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
    } else {
        # Not a mobile device, proceed with wake lock logic
        $flagFilePath = "C:\Temp\WakeLock.flag"
        $wakeLockScriptPath = "C:\Temp\WakeLock.ps1"

        # Write the wake lock logic to a separate PowerShell script file
        @'
        # Load the necessary assembly for accessing Windows Forms functionality
Add-Type -AssemblyName System.Windows.Forms

# Define the path to the flag file
$flagFilePath = 'c:\temp\wakelock.flag'

# Infinite loop to send keys and check for the flag file
while ($true) {
    # Check if the flag file exists
    if (Test-Path $flagFilePath) {
        # If the flag file is found, exit the loop and script
        Write-Host "Flag file detected. Exiting script..."
        break
    } else {
        # If the flag file is not found, send the 'Shift + F15' keys
        [System.Windows.Forms.SendKeys]::SendWait('+{F15}')
        # Wait for 60 seconds before sending the keys again
        Start-Sleep -Seconds 60
    }
}

'@ | Out-File -FilePath $wakeLockScriptPath
    }
} catch {
    Write-Error "Failed to retrieve computer system information. Error: $_"
}
}

Start-Sleep -Seconds 2
Start-Process -FilePath "powershell.exe" -ArgumentList "-file $wakeLockScriptPath" -WindowStyle Minimized
Write-Delayed "Installing required powershell modules..." -NewLine:$false
# Check and Install NuGet Provider if not found
if (-not (Get-PackageSource -Name 'NuGet' -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet  -Scope CurrentUser -Force | Out-Null
    Import-PackageProvider -Name NuGet -Force | Out-Null
    Register-PackageSource -Name NuGet -ProviderName NuGet -Location https://www.nuget.org/api/v2 -Trusted | Out-Null
}
Start-Sleep -Seconds 1
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 

# Stage Procmon
Write-Delayed "Staging Process Monitor..." -NewLine:$false

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

# Disable Notification Snooze
$url = $config.SendWurl
$filePath = $config.TempFolder
# Check if the OS is Windows 11 before running code block
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
if ($osVersion -gt "10.0.22000*") {
    # The code that should only run on Windows 11
    Write-Delayed "Disabling notification snooze..." -NewLine:$false
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
    #[Console]::Write("Disable notification snooze function is only applicable to Windows 11.`n")
}


# Check if the user 'mitsadmin' exists
$user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if ($user.PasswordNeverExpires) {
        Write-Host -ForegroundColor Green " done."
    } else {
        Write-Delayed "Setting mitsadmin password to 'Never Expire'..." -NewLine:$false
        $user | Set-LocalUser -PasswordNeverExpires $true
        Start-Sleep -Seconds 2
        #Write-Log "mitsadmin password set to 'Never Expire'."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor() 
        [Console]::WriteLine()
    }
} else {
    Write-Delayed "Creating local mitsadmin & setting password to 'Never Expire'..." -NewLine:$false
    $Password = ConvertTo-SecureString "@dvances10755" -AsPlainText -Force
    New-LocalUser "mitsadmin" -Password $Password -FullName "MITS Admin" -Description "MITSADMIN Account" *> $null
    $user | set-LocalUser -PasswordNeverExpires $true
    Add-LocalGroupMember -Group "Administrators" -Member "mitsadmin"
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
}


# ConnectWise Automate Agent Installation
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"
$agentIdKeyPath = "HKLM:\SOFTWARE\LabTech\Service"
$agentIdValueName = "ID"

# Check for existing LabTech agent
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    Write-Delayed "ConnectWise Automate agent is installed." -NewLine:$true
} elseif (Test-Path $agentPath) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "ConnectWise Automate agent files are present, but the service is not installed." -NewLine:$true
    [Console]::ResetColor() 
    [Console]::WriteLine()
} else {
    Write-Delayed "Downloading ConnectWise Automate Agent..." -NewLine:$false
    try {
        Invoke-WebRequest -Uri $installerUri -OutFile $file
        Start-Sleep -Seconds 1
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "ConnectWise Automate agent download failed!" -NewLine:$true
        [Console]::ResetColor() 
        [Console]::WriteLine()
        exit
    }
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.`n")
    [Console]::ResetColor()    
    Write-Delayed "Installing ConnectWise Automate Agent..." -NewLine:$false
    $process = Start-Process msiexec.exe -ArgumentList "/I $file /quiet" -PassThru
    $process.WaitForExit()
    if ($process.ExitCode -eq 0) {
        # Wait for the installation to complete
        Start-Sleep -Seconds 60
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
    } else {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" failed.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
        exit
    }
}

$agentServiceName = "LTService" # The name of the service installed by the ConnectWise Automate agent

# Check for the service
$service = Get-Service -Name $agentServiceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if (Test-Path $agentIdKeyPath) {
        # Get the agent ID
        $agentId = Get-ItemProperty -Path $agentIdKeyPath -Name $agentIdValueName -ErrorAction SilentlyContinue
        if ($null -ne $agentId) {
            $LTAID = "Automate Agent ID:"
            foreach ($Char in $LTAID.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30
            }
            Start-Sleep -Seconds 1
            [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
            [Console]::Write(" $($agentId.$agentIdValueName)")
            [Console]::ResetColor()
            [Console]::WriteLine()    
        } else {
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "ConnectWise Automate agent ID not found." -NewLine:$true
            [Console]::ResetColor()
        }
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "ConnectWise Automate agent is not installed." -NewLine:$true
            [Console]::ResetColor()
}
}


# Stop & disable the Windows Update service
Write-Delayed "Suspending Windows Update..." -NewLine:$false

# Stop the Windows Update service
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue *> $null

# Second attempt at stopping Windows Update Service
Start-Sleep -Seconds 5
sc.exe stop wuauserv *> $null

# Set the startup type of the Windows Update service to disabled
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue *> $null
Start-Sleep -Seconds 5


# Get the current status of the Windows Update service
$service = Get-Service -Name wuauserv
Start-Sleep -Seconds 1
# Check if the service is stopped and the startup type is disabled
if ($service.Status -eq 'Stopped') {
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
$registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

# Check if the registry path exists, if not, create it
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force *> $null
}
Write-Delayed "Disabling Offline File Sync..." -NewLine:$false
Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 *> $null
[Console]::ForegroundColor = [System.ConsoleColor]::Green
Start-Sleep -Seconds 2
Write-Log "Offline file sync disabled."
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 2


# Set power profile to 'Balanced'
Write-Delayed "Setting 'Balanced' Power Profile..." -NewLine:$false
Start-Sleep -Seconds 2
powercfg /S SCHEME_BALANCED *> $null
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Write-Log "Power profile set to 'Balanced'."
Start-Sleep -Seconds 5


# Disable sleep and hibernation modes
Start-Sleep -Seconds 1
Write-Delayed "Disabling Sleep & Hibernation..." -NewLine:$false
powercfg /change standby-timeout-ac 0 *> $null
powercfg /change hibernate-timeout-ac 0 *> $null
powercfg /h off *> $null
Start-Sleep -Seconds 2
Write-Log "Disabled sleep and hibernation mode."
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 2


# Disable fast startup
Start-Sleep -Seconds 2
Write-Delayed "Disabling Fast Startup..." -NewLine:$false
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0 *> $null
Write-Log "Fast startup disabled."
#& $config.FastStartup
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 5


# Set power button action to 'Shutdown'
Start-Sleep -Seconds 2
Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
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
    Write-Delayed "Setting 'Do Nothing' lid close action..." -NewLine:$false
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
Write-Delayed "Setting EST as default timezone..." -NewLine:$false
Start-Sleep -Seconds 2
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time" 
Write-Log "Time zone set to Eastern Standard Time."
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 3
Write-Delayed "Syncing system clock..." -NewLine:$false
w32tm /resync -ErrorAction SilentlyContinue | out-null
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()    
Write-Log "Synced system clock"
Start-Sleep -Seconds 5


# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 


# Enable system restore
Write-Delayed "Enabling System Restore..." -NewLine:$false
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-Log "System Restore Enabled."
Start-Sleep -Seconds 2
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
    Write-Delayed "Disabling Windows 10 Offline Files..." -NewLine:$false
    Write-Log "Offline files disabled."
    Start-Sleep -Seconds 1
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    # Write-Host -ForegroundColor yellow " A system restart is required for changes to take effect."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #[Console]::Write("This script is intended to run only on Windows 10.")
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
    Write-Delayed "Disabling Windows 11 Offline Files..." -NewLine:$false
    Write-Log "Offline files disabled."
    Start-Sleep -Seconds 1
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "Windows 11 Offline Files has been disabled"
    #Write-Host -ForegroundColor Yellow " A system restart is required for changes to take effect."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #[Console]::Write("This script is intended to run only on Windows 11.")
}

#Stop-Transcript *> $null

# Check if any application with "Dell" in the name is installed
$dellApps = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Dell*" }

if ($dellApps) {
    # Check if the system is manufactured by Dell
    if ($manufacturer -eq "Dell Inc.") {
        # Set the URL and file path variables
        $SpinnerURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell-Spinner.ps1"
        $SpinnerFile = "c:\temp\Dell-Spinner.ps1"
        $DellSilentURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell_Silent_Uninstall-v2.ps1"
        $DellSilentFile = "c:\temp\Dell_Silent_Uninstall.ps1"
        Set-Location -Path "c:\temp"
        Invoke-WebRequest -Uri $SpinnerURL -OutFile $SpinnerFile -UseBasicParsing -ErrorAction Stop 
        Start-Sleep -seconds 2
        Invoke-WebRequest -Uri $DellSilentURL -OutFile $DellSilentFile -UseBasicParsing -ErrorAction Stop
        if (Test-Path -Path $SpinnerFile) {
            & $SpinnerFile
            Write-Log "Dell Bloatware Removed."
        }
    } else {
        Write-Warning "`nSkipping Dell debloat module due to device not meeting manufacturer requirements.`n"
        Write-Log "Skipping Dell debloat module due to device not meeting manufacturer requirements."
        Start-Sleep -Seconds 1
    }
} else {
    Write-Delayed "Skipping Dell bloatware cleanup as no Dell applications are installed." -NewLine:$true
}

# Kill procmon 
#taskkill /f /im procmon* *> $null

<#
# Registry Check
$OfficeUninstallStrings = (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Microsoft 365 - *"} | Select-Object -ExpandProperty UninstallString)
if ($null -ne $OfficeUninstallStrings) {    
    Invoke-WebRequest -Uri $config.RemoveOfficeURL -OutFile $config.RemoveOfficeScript
    Invoke-WebRequest -Uri $config.RemoveOfficeSpinURL -OutFile $config.RemoveOfficeSpinner
    Invoke-WebRequest -Uri $config.RemoveOneNoteURL -OutFile $config.RemoveOneNoteFile
    Invoke-WebRequest -Uri $config.RemoveOneNoteSpinURL -OutFile $config.RemoveOneNoteSpinner
    Start-Sleep -seconds 2
    if (Test-Path -Path $config.RemoveOfficeSpinner) {
        & $config.RemoveOfficeSpinner
        Start-Sleep -Seconds 5
        & $config.RemoveOneNoteSpinner
        Write-Log "Pre-Installed Office 365 Applications Removed."
        }
} else {
    Write-Delayed " Skipping Pre-Installed Office Removal task due to not meeting application requirements."
    Write-Log "Skipping Pre-Installed Office Removal module due to not meeting application requirements."
    Start-Sleep -Seconds 1
}
#>

Remove-M365 "Microsoft 365 - en-us"                                                        
Remove-M365 "Microsoft 365 - fr-fr"                                                
Remove-M365 "Microsoft 365 - es-es"                                                                                            
Remove-M365 "Microsoft 365 - pt-br"                                               
Remove-M365 "Microsoft OneNote - en-us"                                           
Remove-M365 "Microsoft OneNote - fr-fr"                                         
Remove-M365 "Microsoft OneNote - es-es"                                           
Remove-M365 "Microsoft OneNote - pt-br"                                           


# Restart transcript
#Start-Transcript -Append -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt *> $null

# Check Bitlocker Compatibility
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
    # Check if Bitlocker is already configured on C:
    $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    if ($BitLockerStatus.ProtectionStatus -eq 'On') {
        # Bitlocker is already configured
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Bitlocker is already configured on $env:SystemDrive" -NewLine:$true
        $userResponse = Read-Host "Do you want to skip configuring Bitlocker? (yes/no)"
        if ($userResponse -like 'n') {
            # Disable BitLocker
            manage-bde -off $env:SystemDrive | Out-Null

            # Monitor decryption progress
            do {
                $status = manage-bde -status $env:SystemDrive
                $percentageEncrypted = ($status | Select-String -Pattern "Percentage Encrypted:.*").ToString().Split(":")[1].Trim()
                Write-Host "`rCurrent decryption progress: $percentageEncrypted" -NoNewline
                Start-Sleep -Seconds 1
            } until ($percentageEncrypted -eq "0.0%")
            Write-Host "`nDecryption of $env:SystemDrive is complete."
            # Reconfigure BitLocker
            Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$true
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
            Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
            # Verify volume key protector exists
            $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
            if ($BitLockerVolume.KeyProtector) {
                Write-Host "Bitlocker disk encryption configured successfully."
            } else {
                Write-Host "Bitlocker disk encryption is not configured."
            }
        }
    } else {
        # Bitlocker is not configured
        Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$true
        # Create the recovery key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
        # Add TPM key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 15 # Wait for the protectors to take effect
        # Enable Encryption
        Start-Process 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
        # Backup the Recovery to AD
        $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorID
        manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID | Out-Null
        # Write Recovery Key to a file
        manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"
        # Verify volume key protector exists
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($BitLockerVolume.KeyProtector) {
            Write-Delayed "Bitlocker disk encryption configured successfully." -NewLine:$true
            Write-Host "Recovery ID: $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | ForEach-Object { $_.KeyProtectorId.Trim('{', '}') })"
            Write-Host "Recovery Password: $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | Select-Object -ExpandProperty RecoveryPassword)"
        } else {
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "Bitlocker disk encryption is not configured." -NewLine:$true
            [Console]::ResetColor()
            [Console]::WriteLine()  
        }
    }
} else {
    Write-Warning "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}

# Kill existing instance of procmon
$wshell.SendKeys("^a")
Start-Sleep -Seconds 2
taskkill /f /im procmon64.exe *> $null
Start-Sleep -Seconds 1

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

# Move Procmon to the left
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

# Terminate any existing OfficeClickToRun processes
Write-Delayed "Checking for active OfficeClickToRun processes..." -NewLine:$false
while ($true) {
    # Get the process
    $process = Get-Process -Name "OfficeClickToRun" -ErrorAction SilentlyContinue
    # Check if the process is running
    if ($process) {
        # Terminate the process
        $process | Stop-Process -Force
    } else {
        # If the process is not found, exit the loop
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$true
    [Console]::ResetColor()
        break
    }
    # Wait for a short period before checking again
    Start-Sleep -Seconds 1
}

# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Microsoft Office installation found."
    [Console]::ResetColor()
    goto NE_Install    
} else {
    $OfficePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $OfficePath)) {
        $OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Write-Delayed "Downloading Microsoft Office 365..." -NewLine:$false
        Invoke-WebRequest -OutFile $OfficePath -Uri $OfficeURL -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done."
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        #& $config.officeNotice
        Write-Delayed "Installing Microsoft Office 365..." -NewLine:$false
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Start-Sleep -Seconds 3
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
            Write-Log "Office 365 installation failed."
            Write-Delayed "Microsoft Office 365 installation failed."
            }   
    }
    else {
        # Report download error
        Write-Log "Office download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed or file size does not match."
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 10
        Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
    }
}


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
        Invoke-WebRequest -OutFile $ChromePath -Uri $ChromeURL -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.`n")
        [Console]::ResetColor() 
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $ChromePath).Length
    $ExpectedSize = 1373744 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
       Write-Delayed "Installing Google Chrome..." -NewLine:$false
        Start-Process -FilePath $ChromePath -ArgumentList "/silent /install" -Wait
        Write-Log "Google Chrome installed successfully."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done."
        [Console]::ResetColor()
        [Console]::WriteLine()    
        Start-Sleep -Seconds 10
        Remove-Item -Path $ChromePath -force -ErrorAction SilentlyContinue
    }
    else {
        # Report download error
        Write-Log "Google Chrome download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed or file size does not match."
        [Console]::ResetColor()
        [Console]::WriteLine() 
        Start-Sleep -Seconds 10
        Remove-Item -Path $ChromePath -force -ErrorAction SilentlyContinue
    }
}

# Acrobat Installation
$AcroFilePath = "c:\temp\AcroRead.exe"
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat (64-bit)*" }
Start-Sleep -Seconds 1
if ($Acrobat) {
    Write-Host "Existing Acrobat Reader installation found." -ForegroundColor "Cyan"
} else {
    if (-not (Test-Path $AcroFilePath)) {
        # If not found, download it
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRead.exe"
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $URL -Method Head
        $fileSize = $response.Headers["Content-Length"]
        $ProgressPreference = 'Continue'
        Write-Delayed "Downloading Adobe Acrobat Reader ($fileSize bytes)..." -NewLine:$false
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done."
        [Console]::ResetColor()
        [Console]::WriteLine() 
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1452648 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Adobe Acrobat Reader..." -NewLine:$false
        Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -PassThru | Out-Null
        Start-Sleep -Seconds 150
        # Create a FileSystemWatcher to monitor the specified file
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "C:\Program Files (x86)\Common Files\adobe\Reader\Temp\*"
        $watcher.Filter = "installer.bin"
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName
        $watcher.EnableRaisingEvents = $true
        # When installer.bin is deleted, kill the acroread.exe process
        Register-ObjectEvent $watcher "Deleted" -Action {
            Start-Sleep -Seconds 15
            #& taskkill /f /im acroread.exe
            #Write-Host "acroread.exe process killed" -ForegroundColor "Green"
        } | Out-Null
        function Check-MsiexecSession {
            $msiexecProcesses = Get-Process msiexec -ErrorAction SilentlyContinue
            $hasSessionOne = $msiexecProcesses | Where-Object { $_.SessionId -eq 1 }
        
            return $hasSessionOne
        }
        # Loop to continually check the msiexec process
        do {
        Start-Sleep -Seconds 10  # Wait for 10 seconds before checking again
        $msiexecSessionOne = Check-MsiexecSession
        } while ($msiexecSessionOne)
        # Once there are no msiexec processes with Session ID 1, kill acroread.exe
        Start-Sleep 15
        taskkill /f /im acroread.exe *> $null
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done."
        [Console]::ResetColor()
        [Console]::WriteLine() 
        Write-Log "Adobe Acrobat installation complete." -ForegroundColor Green
        } else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Start-Sleep -Seconds 5
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}


# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }
if ($SWNE) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Sonicwall NetExtender installation found."
    [Console]::ResetColor()   
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
        Write-Delayed "Installing Sonicwall NetExtender..." -NewLine:$false
        start-process -filepath $NEFilePath /S -Wait
        if (Test-Path $config.NEGui) {
            Write-Log "Sonicwall NetExtender installation completed successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done."
            [Console]::ResetColor()
            [Console]::WriteLine()
            Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
        }
    } else {
        # Report download error
        Write-Log "Sonicwall NetExtender download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed! File does not exist or size does not match."
        [Console]::ResetColor()
        [Console]::WriteLine()    
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
    }
}

# Remove Microsoft OneDrive
try {
    $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
    if ($OneDriveProduct) {
        Write-Delayed "Removing Microsoft OneDrive (Personal)..." -NewLine:$false
        $OneDriveProduct | ForEach-Object { $_.Uninstall() } *> $null
        # Recheck if OneDrive is uninstalled
        $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
        if (-not $OneDriveProduct) {
            Write-Log "OneDrive has been successfully removed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done."
            [Console]::ResetColor()
            [Console]::WriteLine()    
        } else {
            Write-Log "Failed to remove OneDrive."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "Failed to remove OneDrive."
            [Console]::ResetColor()
            [Console]::WriteLine()    
        }
    } else {
            Write-Delayed "OneDrive installation not found."
            [Console]::ResetColor()
            [Console]::WriteLine()
    }
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "An error occurred: $_"
    [Console]::ResetColor()
    [Console]::WriteLine()
}


# Remove Microsoft Teams Machine-Wide Installer
try {
    $TeamsMWI = Get-Package -Name 'Teams Machine*'
    if ($TeamsMWI) {
        Write-Delayed "Removing Microsoft Teams Machine-Wide Installer..." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
        Get-Package -Name 'Teams Machine*' | Uninstall-Package *> $null
        $MWICheck = Get-Package -Name 'Teams Machine*'
        if (-not $MWICheck) {
            Write-Log "Teams Machine Wide Installer has been successfully uninstalled."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done."
            [Console]::ResetColor()
            [Console]::WriteLine()   
        } else {
            Write-Log "Failed to uninstall Teams Machine Wide Installer."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "Failed to uninstall Teams Machine Wide Installer."
            [Console]::ResetColor()
            [Console]::WriteLine()
        }
    } else {
        Write-Delayed "Teams machine wide installation not found."
        [Console]::ResetColor()
        [Console]::WriteLine()    
    }
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "An error occurred: $_"
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
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent'"
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}') 
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
        Start-Process powershell -ArgumentList "-noexit","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent'"
        Write-Log "Windows 10 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    #Write-Host "This script is intended to run only on Windows 10."
}

# Enable and start Windows Update Service
Write-Delayed "Enabling Windows Update Service..." -NewLine:$false
Set-Service -Name wuauserv -StartupType Manual
Start-Sleep -seconds 3
Start-Service -Name wuauserv
Start-Sleep -Seconds 5
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running') {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    Write-Delayed " done."
    [Console]::ResetColor()
    [Console]::WriteLine() 
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed " failed."
    [Console]::ResetColor()
    [Console]::WriteLine()    
}

# Function to move Process Monitor to the 
function Move-ProcessWindowToTopRight([string]$processName) {
    $process = Get-Process | Where-Object { $_.MainWindowTitle -match $processName } | Select-Object -First 1
    if ($null -eq $process) {
        Write-Delayed "Process not found." -NewLine:$true
        return
    }

    $hWnd = $process.MainWindowHandle
    if ($hWnd -eq [IntPtr]::Zero) {
        Write-Delayed "Window handle not found." -NewLine:$true
        return
    }

    $windowRect = New-Object WinAPI+RECT
    [WinAPI]::GetWindowRect($hWnd, [ref]$windowRect)
    $windowWidth = $windowRect.Right - $windowRect.Left
    $windowHeight = $windowRect.Bottom - $windowRect.Top

    # Get the screen width
    $screenWidth = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width

    # Calculate the x-coordinate for the top right corner
    $x = $screenWidth - $windowWidth
    $y = 0

    [WinAPI]::MoveWindow($hWnd, $x, $y, $windowWidth, $windowHeight, $true)
}

# Installing Windows Updates
#& $config.UpdateNotice
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
    $null = Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath *> $null
    Start-Sleep -seconds 3
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
    Move-ProcessWindowToTopRight -processName "Windows PowerShell" | Out-Null
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "All available Windows updates are installed."  
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "Windows Update execution failed!"
        [Console]::ResetColor()
        [Console]::WriteLine()  
}
 
function Connect-VPN {
    if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
        Write-Delayed "NetExtender detected successfully, starting connection..." -NewLine:$false
        Start-Process C:\temp\ssl-vpn.bat
        Start-Sleep -Seconds 6
        $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"
        if ($connectionProfile) {
            Write-Delayed "The 'Sonicwall NetExtender' adapter is connected to the SSLVPN." -NewLine:$true
        } else {
            Write-Delayed "The 'Sonicwall NetExtender' adapter is not connected to the SSLVPN." -NewLine:$true
        }
    } else {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "SonicWall NetExtender not found"
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
}

#[Console]::Write("`b`bStarting Domain/Azure AD Join Function...`n")
Write-Delayed "Starting Domain/AzureAD Join Task..." -NewLine:$false
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "Failed to download SSL VPN installer: $_"
    [Console]::ResetColor()
    [Console]::WriteLine()
    exit
}
$ProgressPreference = 'Continue'

$choice = Read-Host "Do you want to connect to SSL VPN? (Y/N)"
switch ($choice) {
    "Y" { Connect-VPN }
    "N" { Write-Delayed "Skipping VPN Connection Setup..." -NewLine:$true }
    default { Write-Delayed "Invalid choice. Please enter Y or N." -NewLine:$true }
}
[Console]::WriteLine()
$choice = Read-Host "Do you want to join a domain or Azure AD? (A for Azure AD, S for domain)"
switch ($choice) {
    "S" {
        $username = Read-Host "Enter the username for the domain join operation"
        $password = Read-Host "Enter the password for the domain join operation" -AsSecureString
        $cred = New-Object System.Management.Automation.PSCredential($username, $password)
        $domain = Read-Host "Enter the domain name for the domain join operation"
        try {
            Add-Computer -DomainName $domain -Credential $cred 
            Write-Delayed "Domain join operation completed successfully." -NewLine:$true
        } catch {
            Write-Delayed "Failed to join the domain." -NewLine:$true
        }
    }
    "A" {
        Write-Delayed "Starting Azure AD Join operation using Work or School account..." -NewLine:$true
        Start-Process "ms-settings:workplace"
        Start-Sleep -Seconds 3
        $output = dsregcmd /status | Out-String
        $azureAdJoined = $output -match 'AzureAdJoined\s+:\s+(YES|NO)' | Out-Null
        $azureAdJoinedValue = if($matches) { $matches[1] } else { "Not Found" }
        Write-Delayed "AzureADJoined: $azureAdJoinedValue" -NewLine:$true
    }
    default { Write-Delayed "Invalid choice. Please enter A or S." -NewLine:$true }
}

# Aquire Wake Lock (Prevents idle session & screen lock)
New-Item -ItemType File -Path "c:\temp\WakeLock.flag" -Force *> $null

# Final log entry
Write-Log "Baseline configuration completed successfully."
Write-Delayed "Baseline configuration completed successfully." -NewLine:$true
Stop-Transcript  
Start-Sleep -seconds 1
Invoke-WebRequest -uri "https://raw.githubusercontent.com/wju10755/Baseline/main/BaselineComplete.ps1" -OutFile "c:\temp\BaselineComplete.ps1" -UseBasicParsing
$scriptPath = "c:\temp\BaselineComplete.ps1"
Invoke-Expression "start powershell -ArgumentList '-noexit','-File $scriptPath'"
Write-Host " "
Write-Host " "
Read-Host -Prompt "Press Enter to exit"
