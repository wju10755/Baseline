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
Write-Host -ForegroundColor Cyan "                                                   version 10.5.2";
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
        Write-Delayed "Removing " -NewLine:$false
        Write-Host $appCheck.DisplayName -NoNewline
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString + " /qn /norestart"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
}

Function Remove-App-EXE-SILENT([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString + " -silent"
        cmd /c $uninst
    }
}

Function Remove-App-MSI_EXE-Quiet([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString[1] +  " /qn /restart"
        cmd /c $uninst

    }
}

Function Remove-App-MSI_EXE-S([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString[1] +  " /S"
        cmd /c $uninst
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
}

Function Remove-M365([String]$appName)
{
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like $appName} | Select-Object UninstallString)
    if($null -ne $uninstall){
        Write-Host "Uninstalling $appName"
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
    }
}

Function Check-UninstallString([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-host $appCheck.DisplayName $appCheck.UninstallString
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
$ProcmonURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Procmon.exe"
$ProcmonFile = "c:\temp\Procmon.exe"

# Download Procmon from LabTech server
Invoke-WebRequest -Uri $ProcmonURL -OutFile $ProcmonFile *> $null

if (Test-Path $ProcmonFile)
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
<#
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

# Remove Dell SupportAssist
try {
    Remove-App-MSI-QN "Dell SupportAssist"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 


# Remove Dell Digital Delivery
try {
    Remove-App-MSI-QN "Dell Digital Delivery Services"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 

# Remove Dell Optimizer Core
try {
Remove-App-EXE-SILENT "Dell Optimizer Core"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 

# Remove Dell SupportAssist OS Recovery Plugin for Dell Update
try{
Remove-App-MSI_EXE-S "Dell SupportAssist OS Recovery Plugin for Dell Update"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell SupportAssist Remediation
try{
Remove-App-MSI_EXE-S "Dell SupportAssist Remediation"  
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell Display Manager 2.1
try{
Remove-App-EXE-S-QUOTES "Dell Display Manager 2.1"                                 
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell Peripheral Manager
try {
Remove-App-EXE-S-QUOTES "Dell Peripheral Manager"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell Core Services
try{
Remove-App-MSI-I-QN "Dell Core Services" 
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell Trusted Device Agent
try {
Remove-App-MSI-I-QN "Dell Trusted Device Agent"                                    
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

# Remove Dell Optimizer
try {
Remove-App-MSI-I-QN "Dell Optimizer"                                               
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
#>
# Remove Dell Command | Update for Windows Universal
try {
    Remove-App-MSI-QN "Dell Command | Update for Windows Universal"
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}