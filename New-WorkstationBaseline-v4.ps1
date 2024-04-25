Set-Executionpolicy RemoteSigned -Force *> $null
$ErrorActionPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "c:\temp\baseline.log"

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
Write-Host -ForegroundColor Cyan "                                                   version 10.7.8";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "

############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#
# Function to write text with delay
function Write-Delayed {
    param([string]$Text, [switch]$NewLine = $true)
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 25
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
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

Function Remove-App-MSI-QN([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
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
    $WarningPreference = 'Continue'
}

Function Remove-App-EXE-SILENT([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString + " -silent"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningPreference = 'Continue'
}

Function Remove-App-MSI_EXE-Quiet([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString[1] +  " /qn /restart"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningPreference = 'Continue'
}

Function Remove-App-MSI_EXE-S([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString[1] +  " /S"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningPreference = 'Continue'
}

Function Remove-App-MSI-I-QN([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst = $appCheck.UninstallString.Replace("/I","/X") + " /qn /norestart"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningPreference = 'Continue'
}

Function Remove-App([String]$appName){
    $WarningActionPreference = 'SilentlyContinue'
    $app = Get-AppxPackage -AllUsers $appName
    if($null -ne $app){
        $packageFullName = $app.PackageFullName
        Write-Delayed "Uninstalling " -NewLine:$false
        Write-Delayed $appName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        Remove-AppxPackage -package $packageFullName -AllUsers
        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | Where-Object {$_.Displayname -eq $appName}).DisplayName
        if($null -ne $proPackageFillName){
            Write-Delayed "Uninstalling provisioned "
            Write-Delayed $appName
            Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            [Console]::Write(" done.")
            [Console]::ResetColor()
            [Console]::WriteLine()    
        }
    }
    $WarningPreference = 'Continue'
}

Function Remove-M365([String]$appName)
{
    $WarningActionPreference = 'SilentlyContinue'
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like $appName} | Select-Object UninstallString)
    if($null -ne $uninstall){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningActionPreference = 'Continue'
}

Function Check-UninstallString([String]$appName)
{
    $WarningActionPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed $appCheck.DisplayName $appCheck.UninstallString
    }
    $WarningActionPreference = 'Continue'
}

Function Remove-App-EXE-S-QUOTES([String]$appName)
{
    $WarningPreference = 'SilentlyContinue'
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($null -ne $appCheck){
        Write-Delayed "Removing " -NewLine:$false
        Write-Delayed $appCheck.DisplayName -NewLine:$false
        Write-Delayed "..." -NewLine:$false
        $uninst ="`""+$appCheck.UninstallString+"`"" + " /S"
        cmd /c $uninst
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    $WarningPreference = 'Continue'
}

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



############################################################################################################
#                                             Start Baseline                                               #
#                                                                                                          #
############################################################################################################
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

############################################################################################################
#                                        Profile Customization                                             #
#                                                                                                          #
############################################################################################################

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

    ##Loop and do the same
    foreach ($sid in $UserSIDs) {
        $Period = "Registry::HKU\$sid\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period | Out-Null
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 
    }
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()    
    # Prevent bloatware applications from returning and removes Start Menu suggestions               
    #Write-Host "Adding Registry key to prevent bloatware apps from returning"
    #$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    #$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    #If (!(Test-Path $registryPath)) { 
    #    New-Item $registryPath
    #}
    #Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1
    #
    #If (!(Test-Path $registryOEM)) {
    #    New-Item $registryOEM
    #}
    #Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    #Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    #Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    #Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    #Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    #Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0  
    
    ##Loop through users and do the same
    #foreach ($sid in $UserSIDs) {
    #    $registryOEM = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    #    If (!(Test-Path $registryOEM)) {
    #        New-Item $registryOEM
    #    }
    #    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    #    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    #    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    #    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    #    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    #    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0 
    #}
    
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
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 

    # Disable Wi-fi Sense
    Write-Delayed "Disabling Wi-Fi Sense" -NewLine:$false
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
#                                        Remove Dell Bloatware                                             #
#                                                                                                          #
############################################################################################################
#
# Get the system manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer

# Check if the system is manufactured by Dell
if ($manufacturer -eq "Dell Inc.") {
    #Write-Host "Dell system detected, Removing bloatware..."
<#    
try {
    Remove-App-MSI-QN "Dell SupportAssist" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 
# Remove Dell Digital Delivery
try {
    Remove-App-MSI-QN "Dell Digital Delivery Services" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 
# Remove Dell Optimizer Core
try {
Remove-App-EXE-SILENT "Dell Optimizer Core" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
} 
# Remove Dell SupportAssist OS Recovery Plugin for Dell Update
try{
Remove-App-MSI_EXE-S "Dell SupportAssist OS Recovery Plugin for Dell Update" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell SupportAssist Remediation
try{
Remove-App-MSI_EXE-S "Dell SupportAssist Remediation"  -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Display Manager 2.1
try{
Remove-App-EXE-S-QUOTES "Dell Display Manager 2.1" -ErrorAction SilentlyContinue                                 
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Peripheral Manager
try {
Remove-App-EXE-S-QUOTES "Dell Peripheral Manager" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Core Services
try{
Remove-App-MSI-I-QN "Dell Core Services" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Trusted Device Agent
try {
Remove-App-MSI-I-QN "Dell Trusted Device Agent"  -ErrorAction SilentlyContinue                                  
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Optimizer
try {
Remove-App-MSI-I-QN "Dell Optimizer" -ErrorAction SilentlyContinue                                            
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Command | Update for Windows Universal
try {
    Remove-App-MSI-QN "Dell Command | Update for Windows Universal" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Command | Update for Windows Universal
try {
    Remove-App-MSI-QN "Dell Command | Update for Windows 10" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
# Remove Dell Pair
try {
    Remove-App-EXE-S-QUOTES "Dell Pair" -ErrorAction SilentlyContinue
} catch {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" An error occurred: $_")
    [Console]::ResetColor()
    [Console]::WriteLine()
}
} 

# List of applications to uninstall
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
} 
#>


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
}

############################################################################################################
#                                          Remove HP Bloatware                                             #
#                                                                                                          #
############################################################################################################
# Remove HP Specific Bloatware
if ($manufacturer -like "*HP*") {
    Write-Host "HP sysem detected, Removing bloatware..."
$UninstallPrograms = @(
    "HP Client Security Manager"
    "HP Notifications"
    "HP Security Update Service"
    "HP System Default Settings"
    "HP Wolf Security"
    "HP Wolf Security Application Support for Sure Sense"
    "HP Wolf Security Application Support for Windows"
    "AD2F1837.HPPCHardwareDiagnosticsWindows"
    "AD2F1837.HPPowerManager"
    "AD2F1837.HPPrivacySettings"
    "AD2F1837.HPQuickDrop"
    "AD2F1837.HPSupportAssistant"
    "AD2F1837.HPSystemInformation"
    "AD2F1837.myHP"
    "RealtekSemiconductorCorp.HPAudioControl",
    "HP Sure Recover",
    "HP Sure Run Module"
    "RealtekSemiconductorCorp.HPAudioControl_2.39.280.0_x64__dt26b99r8h8gj"
    "HP Wolf Security - Console"
    "HP Wolf Security Application Support for Chrome 122.0.6261.139"
    "Windows Driver Package - HP Inc. sselam_4_4_2_453 AntiVirus  (11/01/2022 4.4.2.453)"

)
    $WhitelistedApps = @(
)

# Add custom whitelist apps
    # If custom whitelist specified, remove from array
    if ($customwhitelist) {
        $customWhitelistApps = $customwhitelist -split ","
    foreach ($customwhitelistapp in $customwhitelistapps) {
        $WhitelistedApps += $customwhitelistapp
    }        
    }

$HPidentifier = "AD2F1837"

$InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($UninstallPrograms -contains $_.Name) -or ($_.Name -like "^$HPidentifier"))-and ($_.Name -notlike $WhitelistedApps)}

$ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {(($UninstallPrograms -contains $_.DisplayName) -or ($_.DisplayName -like "*$HPidentifier"))-and ($_.DisplayName -notlike $WhitelistedApps)}

$InstalledPrograms = $allstring | Where-Object {$UninstallPrograms -contains $_.Name}

# Remove provisioned packages first
ForEach ($ProvPackage in $ProvisionedPackages) {

    Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."

    Try {
        $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
        Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
    }
    Catch {Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"}
}

# Remove appx packages
ForEach ($AppxPackage in $InstalledPackages) {
                                            
    Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

    Try {
        $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
        Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
    }
    Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
}

# Remove installed programs
$InstalledPrograms | ForEach-Object {

    Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."
    $uninstallcommand = $_.String

    Try {
        if ($uninstallcommand -match "^msiexec*") {
            #Remove msiexec as we need to split for the uninstall
            $uninstallcommand = $uninstallcommand -replace "msiexec.exe", ""
            #Uninstall with string2 params
            Start-Process 'msiexec.exe' -ArgumentList $uninstallcommand -NoNewWindow -Wait
            }
            else {
            #Exe installer, run straight path
            $string2 = $uninstallcommand
            start-process $string2
            }
        Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
    }
    Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
}
# Belt and braces, remove via CIM too
foreach ($program in $UninstallPrograms) {
Get-CimInstance -Classname Win32_Product | Where-Object Name -Match $program | Invoke-CimMethod -MethodName UnInstall
}
#Remove HP Documentation if it exists
if (test-path -Path "C:\Program Files\HP\Documentation\Doc_uninstall.cmd") {
$A = Start-Process -FilePath "C:\Program Files\HP\Documentation\Doc_uninstall.cmd" -Wait -passthru -NoNewWindow
}
# Remove HP Connect Optimizer 
if (test-path -Path 'C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe') {
invoke-webrequest -uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/HPConnOpt.iss" -outfile "C:\temp\HPConnOpt.iss"

&'C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe' @('-s', '-f1C:\temp\HPConnOpt.iss')
}
# Remove remaining items
if (Test-Path -Path "C:\Program Files (x86)\HP\Shared" -PathType Container) {Remove-Item -Path "C:\Program Files (x86)\HP\Shared" -Recurse -Force}
if (Test-Path -Path "C:\Program Files (x86)\Online Services" -PathType Container) {Remove-Item -Path "C:\Program Files (x86)\Online Services" -Recurse -Force}
if (Test-Path -Path "C:\ProgramData\HP\TCO" -PathType Container) {Remove-Item -Path "C:\ProgramData\HP\TCO" -Recurse -Force}
if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Amazon.com.lnk" -PathType Leaf) {Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Amazon.com.lnk" -Force}
if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Angebote.lnk" -PathType Leaf) {Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Angebote.lnk" -Force}
if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TCO Certified.lnk" -PathType Leaf) {Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TCO Certified.lnk" -Force}

Write-Host "HP bloatware removal complete!"
}

############################################################################################################
#                                          Remove Lenovo Bloatware                                         #
#                                                                                                          #
############################################################################################################
# Remove Lenovo specific bloatware
if ($manufacturer -like "Lenovo") {
    Write-Host "Lenovo system detected, Removing bloatware..."
    function UninstallApp {

        param (
            [string]$appName
        )
        # Get a list of installed applications from Programs and Features
        $installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*$appName*" }
        # Loop through the list of installed applications and uninstall them
        foreach ($app in $installedApps) {
            $uninstallString = $app.UninstallString
            $displayName = $app.DisplayName
            Write-Host "Uninstalling: $displayName"
            Start-Process $uninstallString -ArgumentList "/VERYSILENT" -Wait
            Write-Host "Uninstalled: $displayName" -ForegroundColor Green
        }
    }
    # Stop Running Processes
    $processnames = @(
    "SmartAppearanceSVC.exe"
    "UDClientService.exe"
    "ModuleCoreService.exe"
    "ProtectedModuleHost.exe"
    "*lenovo*"
    "FaceBeautify.exe"
    "McCSPServiceHost.exe"
    "mcapexe.exe"
    "MfeAVSvc.exe"
    "mcshield.exe"
    "Ammbkproc.exe"
    "AIMeetingManager.exe"
    "DADUpdater.exe"
    "CommercialVantage.exe"
    )
    foreach ($process in $processnames) {
        write-host "Stopping Process $process"
        Get-Process -Name $process | Stop-Process -Force
        write-host "Process $process Stopped"
    }
    $UninstallPrograms = @(
        "E046963F.AIMeetingManager"
        "E0469640.SmartAppearance"
        "MirametrixInc.GlancebyMirametrix"
        "E046963F.LenovoCompanion"
        "E0469640.LenovoUtility"
        "E0469640.LenovoSmartCommunication"
        "E046963F.LenovoSettingsforEnterprise"
        "E046963F.cameraSettings"
        "4505Fortemedia.FMAPOControl2_2.1.37.0_x64__4pejv7q2gmsnr"
        "ElevocTechnologyCo.Ltd.SmartMicrophoneSettings_1.1.49.0_x64__ttaqwwhyt5s6t"
    )
        # If custom whitelist specified, remove from array
        if ($customwhitelist) {
            $customWhitelistApps = $customwhitelist -split ","
            $UninstallPrograms = $UninstallPrograms | Where-Object { $customWhitelistApps -notcontains $_ }
        }
    $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($_.Name -in $UninstallPrograms))}
    $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {(($_.Name -in $UninstallPrograms))}
    $InstalledPrograms = $allstring | Where-Object {(($_.Name -in $UninstallPrograms))}
    # Remove provisioned packages first
    ForEach ($ProvPackage in $ProvisionedPackages) {
        Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."
        Try {
            $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
            Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
        }
        Catch {Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"}
    }
    # Remove appx packages
    ForEach ($AppxPackage in $InstalledPackages) {                               
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."
        Try {
            $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }
    # Remove any bundled packages
    ForEach ($AppxPackage in $InstalledPackages) {                                          
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."
        Try {
            $null = Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle, Resource -Name $AppxPackage.Name | Remove-AppxPackage -AllUsers
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }
# Remove installed programs
$InstalledPrograms | ForEach-Object {
    Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."
    $uninstallcommand = $_.String
    Try {
        if ($uninstallcommand -match "^msiexec*") {
            #Remove msiexec as we need to split for the uninstall
            $uninstallcommand = $uninstallcommand -replace "msiexec.exe", ""
            #Uninstall with string2 params
            Start-Process 'msiexec.exe' -ArgumentList $uninstallcommand -NoNewWindow -Wait
            }
            else {
            #Exe installer, run straight path
            $string2 = $uninstallcommand
            start-process $string2
            }
        #$A = Start-Process -FilePath $uninstallcommand -Wait -passthru -NoNewWindow;$a.ExitCode
        #$Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
        Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
    }
    Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
}
# Remove via CIM
foreach ($program in $UninstallPrograms) {
    Get-CimInstance -Classname Win32_Product | Where-Object Name -Match $program | Invoke-CimMethod -MethodName UnInstall
    }
    # Get Lenovo Vantage service uninstall string to uninstall service
    $lvs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object DisplayName -eq "Lenovo Vantage Service"
    if (!([string]::IsNullOrEmpty($lvs.QuietUninstallString))) {
        $uninstall = "cmd /c " + $lvs.QuietUninstallString
        Write-Host $uninstall
        Invoke-Expression $uninstall
    }
    # Uninstall Lenovo Smart
    UninstallApp -appName "Lenovo Smart"
    # Uninstall Ai Meeting Manager Service
    UninstallApp -appName "Ai Meeting Manager"
    # Uninstall ImController service
    ##Check if exists
    $path = "c:\windows\system32\ImController.InfInstaller.exe"
    if (Test-Path $path) {
        Write-Host "ImController.InfInstaller.exe exists"
        $uninstall = "cmd /c " + $path + " -uninstall"
        Write-Host $uninstall
        Invoke-Expression $uninstall
    }
    # Invoke-Expression -Command 'cmd.exe /c "c:\windows\system32\ImController.InfInstaller.exe" -uninstall'

    # Remove vantage associated registry keys
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
    #Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue
     # Uninstall AI Meeting Manager Service
     $path = 'C:\Program Files\Lenovo\Ai Meeting Manager Service\unins000.exe'
     $params = "/SILENT"
     if (test-path -Path $path) {
     Start-Process -FilePath $path -ArgumentList $params -Wait
     }
    # Uninstall Lenovo Vantage
    $pathname = (Get-ChildItem -Path "C:\Program Files (x86)\Lenovo\VantageService").name
    $path = "C:\Program Files (x86)\Lenovo\VantageService\$pathname\Uninstall.exe"
    $params = '/SILENT'
    if (test-path -Path $path) {
        Start-Process -FilePath $path -ArgumentList $params -Wait
    }
    ##Uninstall Smart Appearance
    $path = 'C:\Program Files\Lenovo\Lenovo Smart Appearance Components\unins000.exe'
    $params = '/SILENT'
    if (test-path -Path $path) {
        try {
            Start-Process -FilePath $path -ArgumentList $params -Wait
        }
        catch {
            Write-Warning "Failed to start the process"
        }
    }
$lenovowelcome = "c:\program files (x86)\lenovo\lenovowelcome\x86"
if (Test-Path $lenovowelcome) {
    # Remove Lenovo Now
    Set-Location "c:\program files (x86)\lenovo\lenovowelcome\x86"
    # Update $PSScriptRoot with the new working directory
    $PSScriptRoot = (Get-Item -Path ".\").FullName
    invoke-expression -command .\uninstall.ps1
    Write-Host "All applications and associated Lenovo components have been uninstalled." -ForegroundColor Green
}
$lenovonow = "c:\program files (x86)\lenovo\LenovoNow\x86"
if (Test-Path $lenovonow) {
    # Remove Lenovo Now
    Set-Location "c:\program files (x86)\lenovo\LenovoNow\x86"
    # Update $PSScriptRoot with the new working directory
    $PSScriptRoot = (Get-Item -Path ".\").FullName
    invoke-expression -command .\uninstall.ps1
    Write-Host "All applications and associated Lenovo components have been uninstalled." -ForegroundColor Green
}
}

############################################################################################################
#                                        Remove Pre-installed Office                                       #
#                                                                                                          #
############################################################################################################
# Remove Microsoft 365 - en-us
try {
    Remove-M365 "Microsoft 365 - en-us"                                                  
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
# Remove Microsoft 365 - fr-fr
try {
    Remove-M365 "Microsoft 365 - fr-fr"                                                        
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
# Remove-M365 Microsoft 365 - es-es
try {
    Remove-M365 "Microsoft 365 - es-es"                                                    
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }                                
# Remove-M365 "Microsoft 365 - pt-br
try {
    Remove-M365 "Microsoft 365 - es-es"                                                    
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }

############################################################################################################
#                                       Remove Pre-installed OneNote                                       #
#                                                                                                          #
############################################################################################################
# Remove-M365 Microsoft OneNote - en-us
try {
    Remove-M365 "Microsoft OneNote - en-us"                                                      
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }                                             
# Remove-M365 Microsoft OneNote - fr-fr
try {
    Remove-M365 "Microsoft OneNote - fr-fr"                                                     
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }                                         
# Remove-M365 Microsoft OneNote - es-es
try {
    Remove-M365 "Microsoft OneNote - es-es"                                                   
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
    }                                        
# Remove-M365 Microsoft OneNote - pt-br
try {
    Remove-M365 "Microsoft OneNote - pt-br"                                                    
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" An error occurred: $_")
        [Console]::ResetColor()
        [Console]::WriteLine()
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

# Launch Procmon
#$ps = Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
#$wshell = New-Object -ComObject wscript.shell
#Start-Sleep -Seconds 3
#$wshell.SendKeys("^a")
#Start-Sleep -Seconds 2
#Move-ProcessWindowToTopLeft -processName "procmon64" *> $null
#Start-Sleep -Seconds 2

# Terminate any existing OfficeClickToRun processes
Write-Delayed "Checking for active OfficeClickToRun processes..." -NewLine:$false
while ($true) {
    # Get the process
    $process = Get-Process -Name "OfficeClickToRun" -ErrorAction SilentlyContinue
    # Check if the process is running
    if ($process) {
        # Terminate the process
        $process | Stop-Process -Force
    }
    Start-Sleep -Seconds 1
    break 
    # Wait for a short period before checking again
}
[Console]::ForegroundColor = [System.ConsoleColor]::Green
Write-Delayed " done." -NewLine:$false
[Console]::ResetColor()
[Console]::WriteLine

<#
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
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Microsoft Office 365..." -NewLine:$false
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Start-Sleep -Seconds 10
            Start-Process -FilePath $OfficePath -Wait
            Start-Sleep -Seconds 30
        if (!(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"})) {
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
            Write-Delayed "Microsoft Office 365 installation failed." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()  

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

<#
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
    $FilePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        Write-Delayed "Downloading Microsoft Office..." -NewLine:$false
        Invoke-WebRequest -OutFile c:\temp\OfficeSetup.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe" -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
            }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 7651616 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        Write-Delayed "Installing Microsoft Office..." -NewLine:$false
        Start-Process -FilePath "C:\temp\Officesetup.exe" -Wait
        Write-Log "Office 365 Installation Completed Successfully."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Delayed " done." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()
    }
    else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Office download failed!"
        Start-Sleep -Seconds 10
        #Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}
#>

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
    $ExpectedSize = 7651616 # in bytes
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

# Acrobat Installation
$AcroFilePath = "c:\temp\AcroRead.exe"
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat (64-bit)*" }
Start-Sleep -Seconds 1
if ($Acrobat) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Delayed "Existing Acrobat Reader installation found." -NewLine:$false
    [Console]::ResetColor()
    [Console]::WriteLine() 
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
        Write-Delayed " done." -NewLine:$false
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

<#
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

        } else {
            Write-Log "Failed to remove OneDrive."
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed " failed." -NewLine:$false
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
#>
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
############################################################################################################
#                                            LocalAD/AzureAD Join                                          #
#                                                                                                          #
############################################################################################################
#
Write-Host " "
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
        Write-Delayed "`nStarting Azure AD Join operation using Work or School account..." -NewLine:$true
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
