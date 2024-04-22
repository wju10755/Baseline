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
    if($appCheck -ne $null){
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
    if($appCheck -ne $null){
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
    if($appCheck -ne $null){
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
    if($appCheck -ne $null){
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
    if($appCheck -ne $null){
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
    if($app -ne $null){
        $packageFullName = $app.PackageFullName
        Write-Host "Uninstalling $appName"
        Remove-AppxPackage -package $packageFullName -AllUsers
        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName
        if($proPackageFillName -ne $null){
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
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like $appName} | Select UninstallString)
    if($uninstall -ne $null){
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
    if($appCheck -ne $null){
        Write-host $appCheck.DisplayName $appCheck.UninstallString
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-EXE-S-QUOTES([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
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


# Print Script Title
#################################
$Padding = ("=" * [System.Console]::BufferWidth);
Write-Host -ForegroundColor "Red" $Padding -NoNewline;
Print-Middle "MITS - New Workstation Baseline Script";
Write-Host -ForegroundColor Cyan "                                                   version 10.3.6";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "

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
$flagFilePath = "C:\Temp\WakeLock.flag"
# Get computer system information using CIM (more efficient and modern compared to WMI)
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType

    # Check if the system is a mobile device
    if ($pcSystemType -eq 2) {
        # Mobile device detected, launching presentation settings
        Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
    } else {
        # Not a mobile device, proceed with wake lock logic
        $wakeLockScriptPath = "C:\Temp\WakeLock.ps1"

        # Write the wake lock logic to a separate PowerShell script file
        $wakeLockScript = @'
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
'@

        Set-Content -Path $wakeLockScriptPath -Value $wakeLockScript
    }
} catch {
    Write-Error "Failed to retrieve computer system information. Error: $_"
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
