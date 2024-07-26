# Check if the script is running as an administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!"
    Start-Sleep -Seconds 8
    return
}

Set-Executionpolicy RemoteSigned -Force *> $null
$ErrorActionPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "c:\temp\baseline.log"

#irm "https://raw.githubusercontent.com/wju10755/o365AuditParser/master/Check-Modules.ps1" | Invoke-Expression

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
Write-Host -ForegroundColor Cyan "                                                   version 11.0.9";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "


############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Functions
# Function to write text with delay
function Write-Delayed {
    param(
        [string]$Text, 
        [switch]$NewLine = $true,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    $currentColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 25
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
    [Console]::ForegroundColor = $currentColor
}

# Create temp directory and baseline log
function Initialize-Environment {
    if (-not (Test-Path $TempFolder)) {
        New-Item -Path $TempFolder -ItemType Directory | Out-Null
    }
    if (-not (Test-Path LogFile)) {
        New-Item -Path LogFile -ItemType File | Out-Null
    }
}

# Set working directory
Set-Location
# Baseline Operations Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Message"
}

############################################################################################################
#                                             Start Baseline                                               #
#                                                                                                          #
############################################################################################################
#region Start Baseline
# Start baseline transcript log
Start-Transcript -path c:\temp\$env:COMPUTERNAME-baseline_transcript.txt

# Start Baseline
[Console]::ForegroundColor = [System.ConsoleColor]::Yellow
[Console]::Write("`n")
[Console]::Write("`n")
Write-Delayed "Starting workstation baseline..." -NewLine:$false
[Console]::Write("`n")
[Console]::ResetColor() 
[Console]::WriteLine()
Start-Sleep -Seconds 1

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
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait('~');
if ((Get-Packageprovider -Name NuGet) -eq $null) {
    #Write-Output 'NuGet package provider not found!'
    #Write-Output 'Installing NuGet 2.8.5.201 Provider, Please Wait..'
    try {
        Install-Packageprovider -name nuget -requiredVersion 2.8.5.201 -force -ErrorAction Stop | Out-Null
        #Write-Output 'NuGet package provider installed successfully.'
    } catch {
        #Write-Output "Failed to install NuGet package provider: $_"
    }
} else {
    #Write-Output 'NuGet package provider is installed!'
}

#Write-Output ' Done.'


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait('~');
#Write-Host
#Write-Host
#Write-Host 'Validating Availability of PSWindows Update Module, Please Wait...' 
if ((Get-Module -Name PSWindowsUpdate) -eq $null) {
    #Write-Host -ForegroundColor Yellow 'PSWindowsUpdate module not found!'
    #Write-Host 'Installing PSWindowsUpdate Module, Please Wait...'
    Install-Module -name PSWindowsUpdate -force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    }
Write-Host -ForegroundColor Green 'done.'


# New Module Loader
<#
# List of required modules
$requiredModules = @('MSOnline', 'AzureAD', 'ExchangeOnlineManagement')

foreach ($module in $requiredModules) {
    # Check if the module is installed
    $moduleInstalled = Get-Module -ListAvailable -Name $module
    if (!$moduleInstalled) {
        Write-Host "Module $module is not installed. Installing now..."
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -Confirm:$false
        Write-Host -ForegroundColor Green "$module installed."
    } else {
        Write-Host -ForegroundColor Green "Module $module is installed."
    }
    # Import the module
    Import-Module -Name $module -ErrorAction SilentlyContinue
    #Write-Host -ForegroundColor Green "$module imported successfully."
}
#>








# Stop & disable the Windows Update service
Write-Host "Suspending Windows Update..." -NoNewline

try {
    # Stop the Windows Update service
    Stop-Service -Name wuauserv -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

    # Set the startup type of the Windows Update service to disabled
    Set-Service -Name wuauserv -StartupType Disabled -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

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


############################################################################################################
#                                        Profile Customization                                             #
#                                                                                                          #
############################################################################################################
#region Profile Settings
# Check if the user 'mitsadmin' exists
$user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if ($user.PasswordNeverExpires) {
        Start-Sleep -Milliseconds 700
        Write-Host " done." -ForegroundColor Green
    } else {
        Write-Delayed "Setting mitsadmin password to 'Never Expire'..." -NewLine:$false
        $user | Set-LocalUser -PasswordNeverExpires $true
        Start-Sleep -Milliseconds 700
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.") 
        [Console]::ResetColor()
        [Console]::WriteLine()    
    }
} else {
    Write-Host "Creating local mitsadmin & setting password to 'Never Expire'..." -NoNewline
    $Password = ConvertTo-SecureString "@dvances10755" -AsPlainText -Force
    New-LocalUser "mitsadmin" -Password $Password -FullName "MITS Admin" -Description "MITSADMIN Account" *> $null
    $user | Set-LocalUser -PasswordNeverExpires $true
    Add-LocalGroupMember -Group "Administrators" -Member "mitsadmin"
    Start-Sleep -Milliseconds 700
    Write-Host " done." -ForegroundColor Green
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

# Power Configuration
$pcSystemType = (Get-WmiObject -Class Win32_ComputerSystem).PCSystemType
$activeScheme = (powercfg -getactivescheme).Split()[3]

if ($pcSystemType -eq 2) {
    Write-Delayed "Configuring Mobile Device Power Profile..." -NewLine:$false
    Start-Sleep -Seconds 2  
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
    Write-Delayed "Disabling Fast Startup..." -NewLine:$false
    $regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0 *> $null
    Write-Log "Fast startup disabled."
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    Start-Sleep -Seconds 5
}

# Common configuration for both Mobile and Desktop/Workstation Devices
Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
Start-Sleep -Seconds 2
Write-Log "Power button action set to 'Shutdown'."
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Write-Delayed "Setting 'Do Nothing' lid close action..." -NewLine:$false
Start-Sleep -Seconds 2
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
Write-Log "'Lid close action' set to Do Nothing. (Laptop)"
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()
Write-Delayed "Setting Standby Idle time to 2 hours on battery..." -NewLine:$false
powercfg -setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 7200
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Write-Delayed "Setting Standby Idle time to never on AC power..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()
Write-Delayed "Activating 'Balanced' Power Profile..." -NewLine:$false
powercfg /S $activeScheme
Start-Sleep -Seconds 1
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()

if ($pcSystemType -ne 1 -and $pcSystemType -ne 2 -and $pcSystemType -ne 3) {
    Write-Output "No action needed for system type $pcSystemType."
}

# Set the time zone to 'Eastern Standard Time'
Write-Delayed "Setting EST as default timezone..." -NewLine:$false
Start-Sleep -Seconds 1
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time" 
Write-Log "Time zone set to Eastern Standard Time."
Start-Sleep -Seconds 1
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine() 
Start-Sleep -Seconds 2y
Write-Delayed "Syncing system clock..." -NewLine:$false
w32tm /resync -ErrorAction SilentlyContinue | out-null
Start-Sleep -Seconds 2
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor()
[Console]::WriteLine()    
Write-Log "Synced system clock"
Start-Sleep -Seconds 2


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
Start-Sleep -Seconds 3

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

    # Write-Host -ForegroundColor yellow " A system restart is required for changes to take effect."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
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

# Disable Windows Feedback Experience
    Write-Delayed "Disabling Windows Feedback Experience program..." -newline:$false
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (!(Test-Path $Advertising)) {
        New-Item $Advertising | Out-Null
    }
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0
        Start-Sleep -Milliseconds 500
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
    }
            
    # Stop Cortana from being used as part of your Windows Search Function
    Write-Delayed "Preventing Cortana from being used in Windows Search..." -NewLine:$false
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (!(Test-Path $Search)) {
        New-Item $Search | Out-Null
    }
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0
        Start-Sleep -Milliseconds 500
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()     
    }

    # Disable Web Search in Start Menu
    Write-Delayed "Disabling Bing Search in Start Menu..." -NewLine:$false
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch | Out-Null
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1 

    # Loop through all user SIDs in the registry and disable Bing Search
    foreach ($sid in $UserSIDs) {
        $WebSearch = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
        If (!(Test-Path $WebSearch)) {
            New-Item $WebSearch
        }
        Set-ItemProperty $WebSearch BingSearchEnabled -Value 0
    }
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()     

            
    #Stop Windows Feedback Experience from sending anonymous data
    Write-Delayed "Stopping the Windows Feedback Experience program..." -newline:$false
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 
    Start-Sleep -Milliseconds 500
    ##Loop and do the same
    foreach ($sid in $UserSIDs) {
        $Period = "Registry::HKU\$sid\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period | Out-Null
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
    
    # Prep mixed Reality Portal for removal    
    Write-Delayed "Disabling Mixed Reality Portal..." -NewLine:$false
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
    }

    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Holo = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Holographic"    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo  FirstRunSucceeded -Value 0    
        }
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 

    # Disable Wi-fi Sense
    Write-Delayed "Disabling Wi-Fi Sense..." -NewLine:$false
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1 | Out-Null
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2 | Out-Null
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
        
    # Disable live tiles
    Write-Delayed "Disabling live tiles..." -NewLine:$false
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live | Out-Null
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 

    # Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Live = "Registry::HKU\$sid\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
        If (!(Test-Path $Live)) {      
            New-Item $Live | Out-Null
        }
        Set-ItemProperty $Live  NoTileApplicationNotification -Value 1    
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 

# Disable People icon on Taskbar
    Write-Delayed "Disabling People icon on Taskbar..." -NewLine:$false
    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0  
    }

    # Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $People = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0
        }
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()  

    Write-Delayed "Disabling Cortana..." -NewLine:$false
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    If (!(Test-Path $Cortana1)) {
        New-Item $Cortana1
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
    If (!(Test-Path $Cortana2)) {
        New-Item $Cortana2
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
    If (!(Test-Path $Cortana3)) {
        New-Item $Cortana3
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0

    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Cortana1 = "Registry::HKU\$sid\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 0 
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 

    #Removes 3D Objects from the 'My Computer' submenu in explorer
    Write-Delayed "Removing 3D Objects from explorer 'My Computer' submenu..." -NewLine:$false
    $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (Test-Path $Objects32) {
        Remove-Item $Objects32 -Recurse 
    }
    If (Test-Path $Objects64) {
        Remove-Item $Objects64 -Recurse 
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
   
    # Remove Microsoft Feeds
    Write-Delayed "Removing Microsoft Feeds..." -NewLine:$false
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
    $Name = "EnableFeeds"
    $value = "0"

    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }

    else {
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    

    # Kill Cortana again
    Get-AppxPackage - allusers Microsoft.549981C3F5F10 | Remove AppxPackage | Out-Null

    # Disable unnecessary scheduled tasks
    Write-Delayed "Disabling scheduled tasks..." -NewLine:$false
    $task1 = Get-ScheduledTask -TaskName XblGameSaveTaskLogon -ErrorAction SilentlyContinue 
    if ($null -ne $task1) {
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    $task2 = Get-ScheduledTask -TaskName XblGameSaveTask -ErrorAction SilentlyContinue 
    if ($null -ne $task2) {
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    $task3 = Get-ScheduledTask -TaskName Consolidator -ErrorAction SilentlyContinue
    if ($null -ne $task3) {
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    $task4 = Get-ScheduledTask -TaskName UsbCeip -ErrorAction SilentlyContinue
    if ($null -ne $task4) {
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    $task5 = Get-ScheduledTask -TaskName DmClient -ErrorAction SilentlyContinue
    if ($null -ne $task5) {
    Get-ScheduledTask  DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    $task6 = Get-ScheduledTask -TaskName DmClientOnScenarioDownload -ErrorAction SilentlyContinue
    if ($null -ne $task6) {
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Sleep -Milliseconds 500
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    

############################################################################################################
#                                            RMM Deployment                                                #
#                                                                                                          #
############################################################################################################
# ConnectWise Automate Agent Installation
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"
$agentIdKeyPath = "HKLM:\SOFTWARE\LabTech\Service"
$agentIdValueName = "ID"

# Check for existing LabTech agent
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    Write-Delayed "ConnectWise Automate agent detected." -NewLine:$true
} elseif (Test-Path $agentPath) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "ConnectWise Automate agent files are present, but the service is not installed." -NewLine:$false
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

############################################################################################################
#                                       Configure BitLocker Encryption                                     #
#                                                                                                          #
############################################################################################################
# Check Bitlocker Compatibility
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
    $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    if ($BitLockerStatus.ProtectionStatus -eq 'On') {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Bitlocker is already configured on $env:SystemDrive " -NewLine:$false
        [Console]::ResetColor()
        $userResponse = Read-Host -Prompt "Do you want to skip configuring Bitlocker? (yes/no)"

        if ($userResponse -eq 'no') {
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
            Write-Delayed "Recovery ID:" -NewLine:$false
            Write-Host -ForegroundColor Cyan " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | ForEach-Object { $_.KeyProtectorId.Trim('{', '}') })"
            Write-Delayed "Recovery Password:" -NewLine:$false
            Write-Host -ForegroundColor Cyan " $($BitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | Select-Object -ExpandProperty RecoveryPassword)"
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

Write-Delayed "Removing Microsoft OneDrive (Personal)..." -NewLine:$false
# Remove Microsoft OneDrive
try {
    $OneDriveProduct = Get-CimInstance -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
    if ($OneDriveProduct) { 
        $OneDriveProduct | ForEach-Object { 
            try {
                $_.Uninstall() *> $null
            } catch {
                Write-Host "An error occurred during uninstallation: $_"
            }
        }
        # Recheck if OneDrive is uninstalled
        $OneDriveProduct = Get-CimInstance -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
        if (-not $OneDriveProduct) {
            Write-Log "OneDrive has been successfully removed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()
        } else {
            Write-Log "Failed to remove OneDrive."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed " failed." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()
        }
    } else {
        #Write-Host "Microsoft OneDrive (Personal) is not installed."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
} catch {
    Write-Error "An error occurred: $_"
}

Write-Delayed "Removing Microsoft Teams Machine-Wide Installer..." -NewLine:$false
# Remove Microsoft Teams Machine-Wide Installer
try {
    $TeamsMWI = Get-Package -Name 'Teams Machine*' -ErrorAction SilentlyContinue
    if ($TeamsMWI) {
        [Console]::ResetColor()
        [Console]::WriteLine()
        Get-Package -Name 'Teams Machine*' | Uninstall-Package *> $null
        $MWICheck = Get-Package -Name 'Teams Machine*'
        if (-not $MWICheck) {
            Write-Log "Teams Machine Wide Installer has been successfully uninstalled."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()   
        } else {
            Write-Log "Failed to uninstall Teams Machine Wide Installer."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "Failed to uninstall Teams Machine Wide Installer." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()
        }
    } else {
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()    
    }
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "An error occurred: $_" -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine() 
}

############################################################################################################
#                                          Office 365 Installation                                         #
#                                                                                                          #
############################################################################################################
#
# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                             HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Microsoft Office installation found." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine()   
} else {
    $OfficePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $OfficePath)) {
        $OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Write-Delayed "Downloading Microsoft Office 365..." -NewLine:$false
        Invoke-WebRequest -OutFile $OfficePath -Uri $OfficeURL -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7733536 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Microsoft Office 365..." -NewLine:$false
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Start-Sleep -Seconds 10
            Start-Process -FilePath $OfficePath -Wait
            Start-Sleep -Seconds 15
        if (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"}) {
            Write-Log "Office 365 Installation Completed Successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()  
            Start-Sleep -Seconds 10
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
            } else {
            Write-Log "Office 365 installation failed."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "`nMicrosoft Office 365 installation failed." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()  
            }   
    }
    else {
        # Report download error
        Write-Log "Office download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed or file size does not match." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 10
        Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
    }
}

############################################################################################################
#                                        Adobe Acrobat Installation                                        #
#                                                                                                          #
############################################################################################################
#
<#
# Acrobat Installation -v1
$AcroFilePath = "c:\temp\Reader_en_install.exe"
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }
Start-Sleep -Seconds 1
if ($Acrobat) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Acrobat Reader installation found." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine() 
} else {
    if (-not (Test-Path $AcroFilePath)) {
        # If not found, download it
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Reader_en_install.exe"
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $URL -Method Head
        $fileSize = $response.Headers["Content-Length"]
        $ProgressPreference = 'Continue'
        Write-Delayed "Downloading Adobe Acrobat Reader ($fileSize bytes)..." -NewLine:$false
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine() 
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1628608 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Adobe Acrobat Reader..." -NewLine:$false
        Start-Process -FilePath $installerPath -Args "/sAll /msi /norestart /quiet" -Wait
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
        taskkill /f /im Reader_en_install.exe *> $null
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
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
#>

# Acrobat Installation -v2
$AcroFilePath = "c:\temp\Reader_en_install.exe"
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }
Start-Sleep -Seconds 1
if ($Acrobat) {
    Write-Delayed "Existing Acrobat Reader installation found." -NewLine $true
} else {
    if (-not (Test-Path $AcroFilePath)) {
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Reader_en_install.exe"
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $URL -Method Head
        $fileSize = $response.Headers["Content-Length"]
        $ProgressPreference = 'Continue'
        Write-Host "Downloading Adobe Acrobat Reader ($fileSize bytes)..."
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Host " done."
        [Console]::ResetColor()
    }
    
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1628608 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        $installJob = Start-Job -ScriptBlock {
                Start-Process -FilePath $using:AcroFilePath -Args "/sAll /msi /norestart /quiet"
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
                    function Check-MsiexecSession {
                        $msiexecProcesses = Get-Process msiexec -ErrorAction SilentlyContinue
                        $hasSessionOne = $msiexecProcesses | Where-Object { $_.SessionId -eq 1 }
                        return $hasSessionOne
                    }
                    do {
                        Start-Sleep -Seconds 10
                        $msiexecSessionOne = Check-MsiexecSession
                    } while ($msiexecSessionOne)
                    [Console]::ForegroundColor = [System.ConsoleColor]::Green
                    Write-Delayed "Installation complete." -NewLine:$true # Changed message and added new line
                    [Console]::ResetColor()
                    Write-Log "Adobe Acrobat installation complete." -ForegroundColor Green
                    Start-Sleep -Seconds 30
                    Taskkill /f /im Reader_en_install.exe *> $null
                    Start-Sleep -Seconds 30
                    Taskkill /f /im msedge.exe *> $null
                } | Out-Null
        
            }
        }

        do {
            $message = "Installing Adobe Acrobat"
            Write-Host "`r$message" -NoNewline
            Start-Sleep -Seconds 1
        } while ((Get-Job -Id $installJob.Id).State -eq "Running")

        Remove-Job -Id $installJob.Id
    }


############################################################################################################
#                                   SonicWall NetExtender Installation                                     #
#                                                                                                          #
############################################################################################################
#
# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }
if ($SWNE) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Sonicwall NetExtender installation found." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine()   
} else {
    $NEFilePath = "c:\temp\NXSetupU-x64-10.2.337.exe"
    if (-not (Test-Path $NEFilePath)) {
        $NEURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe"
        Invoke-WebRequest -OutFile $NEFilePath -Uri $NEURL -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $NEGUI = "C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NEGui.exe"
    $FileSize = (Get-Item $NEFilePath).Length
    $ExpectedSize = 4788816 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Sonicwall NetExtender..." -NewLine:$false
        start-process -filepath $NEFilePath /S -Wait
        if (Test-Path $NEGui) {
            Write-Log "Sonicwall NetExtender installation completed successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()
            Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        # Report download error
        Write-Log "Sonicwall NetExtender download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed! File does not exist or size does not match." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()    
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}



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
        Start-Sleep -Seconds 2
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%{TAB}') 
        Write-Log "Windows 10 Debloat completed successfully."
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
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
    Write-Delayed " done." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine() 
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed " failed." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine()    
}

# Installing Windows Updates
Write-Delayed "Checking for Windows Updates..." -NewLine:$false
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
    Write-Delayed "Windows Update execution failed!" -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()  
}
Start-Sleep -Seconds 3
function Connect-VPN {
    if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
        Write-Delayed "NetExtender detected successfully, starting connection..." -NewLine:$false
        Start-Process C:\temp\ssl-vpn.bat
        Start-Sleep -Seconds 8
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


############################################################################################################
#                                            LocalAD/AzureAD Join                                          #
#                                                                                                          #
############################################################################################################
#
Write-Delayed "Starting Domain/AzureAD Join Task..." -NewLine:$true

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
do {
    $choice = Read-Host -Prompt "Do you want to connect to SSL VPN? (Y/N)"
    switch ($choice) {
        "Y" {
            Connect-VPN
            $validChoice = $true
        }
        "N" {
            Write-Delayed "Skipping VPN Connection Setup..." -NewLine:$true
            $validChoice = $true
        }
        default {
            Write-Delayed "Invalid choice. Please enter Y or N." -NewLine:$true
            $validChoice = $false
        }
    }
} while (-not $validChoice)

do {
    $choice = Read-Host -Prompt "Do you want to join a domain or Azure AD? (A for Azure AD, S for domain)"
    switch ($choice) {
        "S" {
            $username = Read-Host -Prompt "Enter the username for the domain join operation"
            $password = Read-Host -Prompt "Enter the password for the domain join operation" -AsSecureString
            $cred = New-Object System.Management.Automation.PSCredential($username, $password)
            $domain = Read-Host -Prompt "Enter the domain name for the domain join operation"
            try {
                Add-Computer -DomainName $domain -Credential $cred 
                Write-Delayed "Domain join operation completed successfully." -NewLine:$true
                $validChoice = $true
            } catch {
                Write-Delayed "Failed to join the domain." -NewLine:$true
                $validChoice = $true
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
            $validChoice = $true
        }
        default {
            Write-Delayed "Invalid choice. Please enter A or S." -NewLine:$true
            $validChoice = $false
        }
    }
} while (-not $validChoice)

# Aquire Wake Lock (Prevents idle session & screen lock)
New-Item -ItemType File -Path "c:\temp\WakeLock.flag" -Force *> $null

# Final log entry
Write-Log "Baseline configuration completed successfully."
Write-Delayed "Baseline configuration completed successfully." -NewLine:$true
Write-Host " "
Stop-Transcript  
Start-Sleep -seconds 1
Invoke-WebRequest -uri "https://raw.githubusercontent.com/wju10755/Baseline/main/BaselineComplete.ps1" -OutFile "c:\temp\BaselineComplete.ps1"
$scriptPath = "c:\temp\BaselineComplete.ps1"
Invoke-Expression "start powershell -ArgumentList '-noexit','-File $scriptPath'"
Write-Host " "
Write-Host " "
Read-Host -Prompt "Press enter to exit"
Stop-Process -Id $PID -Force