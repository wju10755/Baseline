Set-Executionpolicy RemoteSigned -Force *> $null
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'

# Clear console window
Clear-Host

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
Write-Host -ForegroundColor Cyan "                                                   version 10.3.8";
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

# Baseline Operations Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $config.LogFile -Value "$(Get-Date) - $Message"
}

Function Remove-App-MSI-QN([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString + " /qn /norestart"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}
Function Remove-App-EXE-SILENT([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString + " -silent"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-MSI_EXE-Quiet([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString[1] +  " /qn /restart"
        cmd /c $uninst

    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-MSI_EXE-S([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString[1] +  " /S"
        cmd /c $uninst

    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-MSI-I-QN([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString.Replace("/I","/X") + " /qn /norestart"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App([String]$appName){
    $app = Get-AppxPackage -AllUsers $appName
    if($null -ne $app){
        $packageFullName = $app.PackageFullName
        Write-Host "Uninstalling $appName"
        Remove-AppxPackage -package $packageFullName -AllUsers
        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | Where-Object {$_.Displayname -eq $appName}).DisplayName
        if($null -ne $proPackageFillName){
            Write-Host "Uninstalling provisioned $appName"
            Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers
        }
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-M365([String]$appName)
{
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like $appName} | Select-Object UninstallString)
    if($null -ne $uninstall){
        Write-Host "Uninstalling $appName"
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Check-UninstallString([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host $appCheck.DisplayName $appCheck.UninstallString
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-EXE-S-QUOTES([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst ="`""+$appCheck.UninstallString+"`"" + " /S"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
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




# Start baseline transcript log
Start-Transcript -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt

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

# Check if the user 'mitsadmin' exists
$user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if ($user.PasswordNeverExpires) {
        Write-Host " done." -ForegroundColor Green
    } else {
        Write-Host "Setting mitsadmin password to 'Never Expire'..." -NoNewline
        $user | Set-LocalUser -PasswordNeverExpires $true
        Write-Host " done." -ForegroundColor Green
    }
} else {
    Write-Host "Creating local mitsadmin & setting password to 'Never Expire'..." -NoNewline
    $Password = ConvertTo-SecureString "@dvances10755" -AsPlainText -Force
    New-LocalUser "mitsadmin" -Password $Password -FullName "MITS Admin" -Description "MITSADMIN Account" *> $null
    $user | Set-LocalUser -PasswordNeverExpires $true
    Add-LocalGroupMember -Group "Administrators" -Member "mitsadmin"
    Write-Host " done." -ForegroundColor Green
}

# Stop & disable the Windows Update service
Write-Host "Suspending Windows Update..." -NoNewline

try {
    # Stop the Windows Update service
    Stop-Service -Name wuauserv -Force -ErrorAction Stop

    # Set the startup type of the Windows Update service to disabled
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop

    # Get the current status of the Windows Update service
    $service = Get-Service -Name wuauserv

    # Check if the service is stopped
    if ($service.Status -eq 'Stopped') {
        Write-Host " done." -ForegroundColor Green
    } else {
        Write-Host " failed." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Disable Offline File Sync
$registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

try {
    # Check if the registry path exists, if not, create it
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force *> $null
    }

    Write-Host "Disabling Offline File Sync..." -NoNewline

    # Set the registry value
    Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 *> $null

    Write-Host " done." -ForegroundColor Green
    Write-Log "Offline file sync disabled."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Set power profile to 'Balanced'
Write-Host "Setting 'Balanced' Power Profile..." -NoNewline

try {
    # Set the power profile
    powercfg /S SCHEME_BALANCED 

    Write-Host " done." -ForegroundColor Green
    Write-Log "Power profile set to 'Balanced'."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Disable sleep and hibernation modes
Write-Host "Disabling Sleep & Hibernation..." -NoNewline

try {
    # Disable standby timeout
    powercfg /change standby-timeout-ac 0 

    # Disable hibernate timeout
    powercfg /change hibernate-timeout-ac 0 

    # Turn off hibernation
    powercfg /h off 

    Write-Host " done." -ForegroundColor Green
    Write-Log "Disabled sleep and hibernation mode."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Disable fast startup
Write-Host "Disabling Fast Startup..." -NoNewline

try {
    $regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0 *> $null
    Write-Host " done." -ForegroundColor Green
    Write-Log "Fast startup disabled."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Set power button action to 'Shutdown'
Write-Host "Configuring 'Shutdown' power button action..." -NoNewline

try {
    # Set the power button action
    powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3 *> $null
    powercfg /SETACTIVE SCHEME_CURRENT *> $null
    & $config.PwrButton

    Write-Host " done." -ForegroundColor Green
    Write-Log "Power button action set to 'Shutdown'."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Set 'lid close action' to do nothing on laptops
if ($deviceType -eq "Laptop") {
    Write-Host "Setting 'Do Nothing' lid close action..." -NoNewline

    try {
        # Set the lid close action
        powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 *> $null
        powercfg /SETACTIVE SCHEME_CURRENT *> $null
        & $config.LidAction

        Write-Host " done." -ForegroundColor Green
        Write-Log "'Lid close action' set to Do Nothing. (Laptop)"
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}

# Set the time zone to 'Eastern Standard Time'
Write-Host "Setting EST as default timezone..." -NoNewline

try {
    Start-Service W32Time
    Set-TimeZone -Id "Eastern Standard Time" 
    Write-Host " done." -ForegroundColor Green
    Write-Log "Time zone set to Eastern Standard Time."

    Write-Host "Syncing system clock..." -NoNewline
    w32tm /resync -ErrorAction SilentlyContinue | Out-Null
    Write-Host " done." -ForegroundColor Green
    Write-Log "Synced system clock"
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
Write-Host "Enabling System Restore..." -NoNewline

try {
    Enable-ComputerRestore -Drive "C:\" -Confirm:$false
    Write-Host " done." -ForegroundColor Green
    Write-Log "System Restore Enabled."
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

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
    Write-Host "Disabling Windows 10 Offline Files..." -NoNewline

    try {
        # Set the path of the Offline Files registry key
        $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

        # Check if the registry path exists, if not, create it
        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force
        }

        # Set the value to disable Offline Files
        Set-ItemProperty -Path $registryPath -Name "Start" -Value 4

        Write-Host " done." -ForegroundColor Green
        Write-Log "Offline files disabled."
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
} else {
    #Write-Host "This script is intended to run only on Windows 10." -ForegroundColor Yellow
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
    Write-Host "Disabling Windows 11 Offline Files..." -NoNewline

    try {
        # Set the path of the Offline Files registry key
        $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

        # Check if the registry path exists, if not, create it
        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force
        }

        # Set the value to disable Offline Files
        Set-ItemProperty -Path $registryPath -Name "Start" -Value 4

        Write-Host " done." -ForegroundColor Green
        Write-Log "Offline files disabled."
        Write-Log "Windows 11 Offline Files has been disabled"
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
} else {
    #Write-Host "This script is intended to run only on Windows 11." -ForegroundColor Yellow
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
    Write-Host "ConnectWise Automate agent is installed." -ForegroundColor Green
} elseif (Test-Path $agentPath) {
    Write-Host "ConnectWise Automate agent files are present, but the service is not installed." -ForegroundColor Red
} else {
    Write-Host "Downloading ConnectWise Automate Agent..." -NoNewline
    try {
        Invoke-WebRequest -Uri $installerUri -OutFile $file
        Write-Host " done." -ForegroundColor Green
        Write-Host "Installing ConnectWise Automate Agent..." -NoNewline
        $process = Start-Process msiexec.exe -ArgumentList "/I $file /quiet" -PassThru
        $process.WaitForExit()
        if ($process.ExitCode -eq 0) {
            Write-Host " done." -ForegroundColor Green
        } else {
            Write-Host " failed." -ForegroundColor Red
            exit
        }
    } catch {
        Write-Host "ConnectWise Automate agent download failed!" -ForegroundColor Red
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
            Write-Host "Automate Agent ID: $($agentId.$agentIdValueName)" -ForegroundColor Cyan
        } else {
            Write-Host "ConnectWise Automate agent ID not found." -ForegroundColor Red
        }
    }
} else {
    Write-Host "ConnectWise Automate agent is not installed." -ForegroundColor Red
}