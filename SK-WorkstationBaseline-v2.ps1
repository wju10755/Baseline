Clear-Host
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
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -force -ErrorAction SilentlyContinue
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'
Start-Transcript -path c:\temp\baseline_transcript.txt
Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
#Write-Host "Starting workstation baseline..." -ForegroundColor "Yellow"=
Write-Output " "
Write-Output " "
Write-Host "Starting workstation baseline..." -ForegroundColor "Yellow"   
Write-Output " "
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
}

# Central Configuration
$config = @{
    PSNoticeUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/psnotice.zip"
    NoSnoozeUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NoSnooze.zip"
    Sikulixide  = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/sikulixide-2.0.5.jar"
    TempFolder           = "C:\temp"
    LogFile              = "C:\temp\baseline.log"
    NoSnooze             = "c:\temp\nosnooze.ps1"
    NoSnoozeZip          = "c:\temp\nosnooze.zip"
    JDKInstallerPath     = "C:\temp\jdk-11.0.17_windows-x64_bin.exe"
    JDKVersion           = "11.0.17"
    JDKArguments         = "/s"
    PSNoticePath         = "c:\temp\PSNotice"
    PSNoticeFile         = "c:\temp\psnotice.zip"
    SikuliFile           = "c:\temp\sikulixide-2.0.5.jar"
    BruSpinner           = "c:\temp\bru-spinner.ps1"
    BRUZip               = "C:\temp\BRU.zip"
    ChromeInstaller      = "c:\temp\ChromeSetup.exe"
    AcrobatInstaller     = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    OfficeInstaller      = "c:\temp\Office2016_ProPlus"
    ClearPath            = "C:\temp\psnotice\Clear-ToastNotification.ps1"
    ChromeNotification   = "C:\temp\psnotice\appnotice\Chrome\New-ToastNotification.ps1"
    AcrobotNotification  = "C:\temp\psnotice\appnotice\acrobat\New-ToastNotification.ps1"
    AcrobatComplete      = "c:\temp\psnotice\appnotice\acrobat\AcrobatComplete.ps1"
    AcrobatFailure       = "C:\temp\psnotice\appnotice\acrobat\failure\New-ToastNotification.ps1"
    OfficeComplete       = "C:\temp\psnotice\OfficeNotice\complete\New-ToastNotification.ps1"
    OfficeFailure        = "C:\temp\psnotice\OfficeNotice\failure\New-ToastNotification.ps1"
    StartBaseline        = "C:\temp\psnotice\BaselineStart\New-ToastNotification.ps1"
    UpdateNotice         = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    UpdateComplete       = "C:\temp\psnotice\psupdate\New-ToastNotification.ps1"
    BaselineComplete     = "C:\temp\psnotice\BaselineComplete\New-ToastNotification.ps1"
    
    # Add other configuration items here...
}

# Ensure essential directories and files exist
function Initialize-Environment {
    if (-not (Test-Path $config.TempFolder)) {
        New-Item -Path $config.TempFolder -ItemType Directory | Out-Null
    }
    if (-not (Test-Path $config.LogFile)) {
        New-Item -Path $config.LogFile -ItemType File | Out-Null
    }
}

# Custom logging function
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $config.LogFile -Value "$(Get-Date) - $Message"
}

# Check for required Powershell Modules
[Console]::Write("Installing Required Powershell Modules...")
if (-not (Get-PackageSource -Name 'NuGet' -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -Confirm:$false
    Import-PackageProvider -Name NuGet -Force -Confirm:$false
    Register-PackageSource -Name NuGet -ProviderName NuGet -Location https://www.nuget.org/api/v2 -Trusted -Confirm:$false
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
Invoke-WebRequest -Uri $config.PSNoticeUrl -OutFile $confgi.PSNoticeFile -UseBasicParsing *> $null
if (Test-Path -Path $config.PSNoticeFile -PathType Leaf) {
    Expand-Archive -Path $config.PSNoticeFile -DestinationPath $config.PSNoticePath -Force
}
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() # Reset the color to default
[Console]::WriteLine() # Move to the next line

[Console]::Write("Staging Anti-Snooze function...")
try {
    Invoke-WebRequest -Uri $config.NoSnoozeUrl -OutFile $config.NoSnoozeZip -ErrorAction Stop
    Start-Sleep -seconds 2
    if (Test-Path -Path $config.NoSnoozeZip -PathType Leaf) {
    Write-Output "Download of NoSnooze was successful."
} else {
    Write-Output "Download of NoSnooze failed."
}
Expand-Archive -Path $config.NoSnoozeZip -DestinationPath $config.TempFolder -Force -ErrorAction Stop
Start-Sleep -Seconds 2
Invoke-WebRequest -Uri $config.Sikulixide -Outfile $config.SikuliFile -ErrorAction Stop
Start-Sleep -Seconds 2
if (Test-Path -Path $config.SikuliFile -PathType Leaf) {
    Write-Output "Download of SikulixIDE was successful."
} else {
    Write-Output "Download of Sikulixide failed."
}

Set-Location $config.TempFolder
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() 
[Console]::WriteLine() 


# Function to check if JDK is installed
function Is-JdkInstalled {
    param (
        [string]$version
    )

    # Check the registry for JDK installation
    try {
        $jdkPath = Get-ChildItem -Path "HKLM:\SOFTWARE\JavaSoft\JDK" -ErrorAction Stop | Get-ItemProperty | Where-Object { $_.JavaHome }
        return $jdkPath -ne $null
    } catch {
        return $false
    }
}

# Check if JDK 11.0.17 is already installed
if (Is-JdkInstalled -version $config.jdkVersion) {
    Write-Host "JDK $jdkVersion is already installed."
} else {
    # Define the path to the JDK installer
    $installerPath = "C:\temp\jdk-11.0.17_windows-x64_bin.exe"

    # Define the silent installation arguments
    $arguments = "/s"

    # Create a new process start info object
    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

    # Set the filename to the installer and add the silent installation arguments
    $processStartInfo.FileName = $installerPath
    $processStartInfo.Arguments = $arguments
    $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processStartInfo.CreateNoWindow = $true
    $processStartInfo.UseShellExecute = $false

    # Start the installation process
    [Console]::Write("Installing Java Development Kit...")
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    $process.WaitForExit()

    # Check the exit code
    if ($process.ExitCode -eq 0) {
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor() 
        [Console]::WriteLine() 

        } else {
            Write-Host "JDK installation failed with exit code: $($process.ExitCode)"
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            [Console]::Write("JDK installation failed with exit code: $($process.ExitCode)")
            [Console]::ResetColor() 
            [Console]::WriteLine() 
    
        }
}

# Trigger NoSnooze
[Console]::Write("Disabling notification snooze...")
set-location -path C:\temp
start-process c:\temp\nosnooze_sikuli.jar
Start-Sleep -Seconds 25
[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() 
[Console]::WriteLine() 

# Start Baseline Notification
& $StartBaseline | Out-Null
Write-Log "Automated workstation baseline has started"

# ConnectWise Automate Agent Installation

# Agent Installer Download Check
$file = 'c:\temp\Warehouse-Agent_Install.MSI'

if ([System.IO.File]::Exists($file)) {
    try {
        Write-Host " done." -ForegroundColor "Green"
    } catch {
        throw $_.Exception.Message
    }    
}
else {
    Write-Host " failed!" -ForegroundColor "Red"
    Write-log "The file [$file] download failed."
}

# Check if the LabTech agent is already installed
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"

if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    Write-Output "The LabTech agent is already installed."
}
elseif (Test-Path $agentPath) {
    Write-Output "The LabTech agent files are present, but the service is not installed."
}
else {
    Write-Host "Installing ConnectWise Automate Agent..." -NoNewline
    Write-Host "Downloading ConnectWise Automate Remote Agent..." -NoNewline   
    Invoke-WebRequest -uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI" -OutFile "c:\temp\Warehouse-Agent_Install.MSI" *> $null
    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\Warehouse-Agent_Install.MSI /quiet'
    Start-Sleep -Seconds 45
    & $clearPath

    # Automate Agent Installation Check
    $folder = 'C:\Windows\LTSvc\'
    if ([System.IO.Directory]::Exists($folder)) {
        try {
            Write-Host " done." -ForegroundColor "Green"
            Write-Log "ConnectWise Automate Agent Installation Completed Successfully!"
        } catch {
            throw $_.Exception.Message
        }    
    }
    else {
        Write-Host " failed!" -foregroundcolor red
        Write-Log "ConnectWise Automate Agent installation failed!"
    }
}

# Identify device manufacturer and type
$computerSystem = Get-WmiObject Win32_ComputerSystem
$manufacturer = $computerSystem.Manufacturer
$deviceType = if ($computerSystem.PCSystemType -eq 2) { "Laptop" } else { "Desktop" }
Write-Host "Identifying device type: " -NoNewline
Start-Sleep -Seconds 2
Write-Host $deviceType -ForegroundColor "Yellow"
Write-Log "Manufacturer: $manufacturer, Device Type: $deviceType."
New-BurntToastNotification -Text "Identified device type: $manufacturer $deviceType" -AppLogo "$PSNotice\smallA.png"
& $clearPath
Start-Sleep -Seconds 2

# Set power profile to 'Balanced'
Write-Host "Setting Power Profile..." -NoNewLine
Start-Sleep -Seconds 3
powercfg /S SCHEME_BALANCED
New-BurntToastNotification -Text "Power profile set to Balanced" -AppLogo "$PSNotice\smallA.png"
Write-Host " done." -ForegroundColor "Green"
Write-Log "Power profile set to 'Balanced'."
Start-Sleep -Seconds 5
& $clearPath

# Disable sleep and hibernation modes
Start-Sleep -Seconds 1
Write-Host "Disabling Sleep and Hibernation..." -NoNewline
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /h off
New-BurntToastNotification -Text "Sleep and hibernation settings disabled" -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Write-Log "Disabled sleep and hibernation modes."
Start-Sleep -Seconds 5
& $clearPath

# Disable fast startup
Start-Sleep -Seconds 1
Write-Host "Disabling Fast Startup..." -NoNewline
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0
Write-Log "Disabled fast startup."
New-BurntToastNotification -Text "Fast startup disabled" -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 5
& $clearPath

# Set power profile
Start-Sleep -Seconds 1
Write-Host "Configuring power profile..." -NoNewline
powercfg /SETACTIVE SCHEME_CURRENT
New-BurntToastNotification -Text "Power profile set to 'Balanced'" -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"

# Set power button action to 'Shutdown'
Start-Sleep -Seconds 2
Write-Host "Configuring power button action to shutdown..." -NoNewline
powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /SETACTIVE SCHEME_CURRENT
New-BurntToastNotification -Text "Power button action set to 'Shutdown'" -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 3
Write-Host " done." -ForegroundColor "Green"
Write-Log "Set power button action to 'Shutdown'."
Start-Sleep -Seconds 5
& $clearPath

# Set 'lid close action' to do nothing on laptops
Start-Sleep -Seconds 1
if ($deviceType -eq "Laptop") {
    Write-Host "Setting Lid Close Action..." -NoNewline
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /SETACTIVE SCHEME_CURRENT
    Write-Log "Set 'lid close action' to Do Nothing on laptop."
    New-BurntToastNotification -Text "Lid close action set to 'Do Nothing'" -AppLogo "$PSNotice\smallA.png"
    Start-Sleep -Seconds 2
    Write-Host " done." -ForegroundColor "Green"
    Start-Sleep -Seconds 5
    & $clearPath
}

# Set the time zone to 'Eastern Standard Time'
Write-Host "Setting EST as default timezone..." -NoNewline
Start-Service W32Time
Set-TimeZone -Id "Eastern Standard Time"
Write-Log "Time zone set to Eastern Standard Time."
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 2
Write-Host "Syncing clock..." -NoNewline
w32tm /resync -ErrorAction SilentlyContinue | out-null
New-BurntToastNotification -Text "Default timezone set to 'EST'." -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"    
Start-Sleep -Seconds 5
& $clearPath

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Write-Host "Configuring System Restore..." -NoNewLine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-Log "System restore enabled."

# Create restore point
Checkpoint-Computer -Description 'Baseline Settings' -RestorePointType 'MODIFY_SETTINGS'
$restorePoint = Get-ComputerRestorePoint | Sort-Object -Property "CreationTime" -Descending | Select-Object -First 1
if ($restorePoint -ne $null) {
    Write-Output "Restore point created successfully"
} else {
    Write-Output "Failed to create restore point"
}
New-BurntToastNotification -Text "System restore is now enabled" -AppLogo "$PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 5
& $clearPath

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

# Check if Dell Peripheral Manager is installed
Write-Host "Starting Dell bloatware removal`n" -NoNewline
$DPMpackageName = 'Dell Peripheral Manager'
$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue

if ($DPMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    #Write-Host "Downloading Dell Peripheral Manager Script..."
    Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip *> $null

    # Extract the file
    Write-Host "Extracting Dell Peripheral Manager package..."
    Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force

    # Run the script
    Write-Host "Removing Dell Peripheral Manager..."
    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

# Check if Dell Display Manager is installed
$DDMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-ddm.zip"
$DDMzip = "C:\temp\Uninstall-ddm.zip"
$DDMdir = "C:\temp\Uninstall-DDM"
$DDMpackageName = 'Dell Display Manager'

$DDMpackage = Get-Package -Name $DDMpackageName -ErrorAction SilentlyContinue

if ($DDMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $DDMurl -OutFile $DDMzip *> $null

    # Extract the file
    Write-Host "Extracting Dell Display Manager package..."
    Expand-Archive -Path $DDMzip -DestinationPath $DDMdir -Force

    # Run the script
    Write-Host "Removing Dell Display Manager..." -NoNewline
    & "$DDMdir\Uninstall-DellDisplayManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell Display Manager."
} else {
    Write-Host "Dell Display Manager not found" -ForegroundColor "Red"
}

    
# Remove Dell Optimizer Core
#if (test-path -path "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe" ) {invoke-command -scriptblock {'C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe'} -ArgumentList "-remove -runfromtemp"}
$optimizerPath = "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe"
if (Test-Path $optimizerPath) {
    Write-Host "Removing Dell Optimizer Core..." -NoNewline
    $command = "`"$optimizerPath`" -remove -runfromtemp -silent"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -NoNewWindow -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell Optimizer Core."
} else {
    Write-Host "Dell Optimizer Core installation not found." -foregroundColor "Red"
}
    
# Remove Dell Command Update (All Versions)
$Name = "Dell Command | Update*"
$ProcName = "DellCommandUpdate"
$Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
$LogFile = "C:\temp\Dell-CU-Uninst_$Timestamp.log"
$ProgramList = @( "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" )
$Programs = Get-ItemProperty $ProgramList -EA 0
$App = ($Programs | Where-Object { $_.DisplayName -like $Name -and $_.UninstallString -like "*msiexec*" }).PSChildName

if ($App) {
    Get-Process | Where-Object { $_.ProcessName -eq $ProcName } | Stop-Process -Force
    $Params = @(
        "/qn"
        "/norestart"
        "/X"
        "$App"
        "/L*V ""$LogFile"""
        )
        Write-Host "Removing Dell Command Update..." -NoNewline
        Start-Process "msiexec.exe" -ArgumentList $Params -Wait -NoNewWindow
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Removed Dell Command Update."
}
else {
    Write-Host "$Name installation not found." -foregroundColor "Red"
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

# Dell Support Assist Remediation Service
$filePath = "C:\ProgramData\Package Cache\{b2e99ca2-5292-470d-bf98-4d347c913748}\DellSupportAssistRemediationServiceInstaller.exe"
if (Test-Path $filePath) {
    Write=Host "Removing Dell Support Assist Remediation Service..." -NoNewline
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$filePath`" /uninstall /quiet" -NoNewWindow -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Dell Support Assist Remediation Service removed."
} else {
    Write-Host "Support Assist Remediation Service not found." -foregroundColor "Red"   
}

# Dell Support Assist OS Recovery Plugin for Dell Update
$DSARP = "C:\ProgramData\Package Cache\{9d6ba6ac-00ed-41bc-9a72-368346191765}\DellUpdateSupportAssistPlugin.exe"
if (Test-Path $DSARP) {
    Write-Host "Removing Dell Support Assist OS Recovery Plugin for Dell Update..." -NoNewline
    Start-Process -FilePath "$DSARP" -ArgumentList "/uninstall" -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Dell Support Assist OS Recovery Plugin for Dell Update removed."
    Start-Sleep -Seconds 15
    taskkill /f /im DellUpdateSupportAssistPlugin.exe *> $null

} else {
    Write-Host "Dell Support Assist OS Recovery Plugin for Dell Update not found" -ForegroundColor "Yellow"
}


# Remove Dell SupportAssist
$exePath = "C:\ProgramData\Package Cache\{2600102a-dac2-4b2a-8257-df60c573fc29}\DellUpdateSupportAssistPlugin.exe"
if (Test-Path $exePath) {
    Write-Host "Removing Dell SupportAssist..." -NoNewline
    $command = "`"$exePath`" /uninstall /quiet"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell SupportAssist."
    Start-Sleep -Seconds 3
        } else {
        #Write-Host "DellUpdateSupportAssistPlugin.exe does not exist."
        Write-Host "Dell SupportAssist installation not found." -ForegroundColor "Red"
    }

# Remove Support Assist v2
$ProgressPreference = 'SilentlyContinue'
$RevoURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/RevoCMD.zip"
$RevoFile = "c:\temp\RevoCMD.zip"
$RevoDestination = "c:\temp\RevoCMD"

# Download RevoCMD.zip
Invoke-WebRequest -Uri $RevoURL -OutFile $RevoFile -ErrorAction SilentlyContinue

# Check if RevoCMD.zip exists
if (Test-Path -Path $RevoFile) {
    # Extract RevoCMD.zip
    Expand-Archive -Path $RevoFile -DestinationPath $RevoDestination -Force
    
    # Run RevoUnPro with specified parameters
    Start-Process -FilePath "$RevoDestination\RevoUnPro.exe" -ArgumentList "/mu 'Dell SupportAssist' /path 'C:\Program Files\Dell\SupportAssistAgent' /mode Moderate /32"
}


# Download and run Bloatware Removal Utility
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/BRU.zip" -OutFile "c:\temp\BRU.zip" 
if (Test-Path "c:\temp\BRU.zip" -PathType Leaf) {
  Expand-Archive -Path "c:\temp\BRU.zip" -DestinationPath "c:\BRU\" -Force *> $null
  Set-Location c:\bru\
  Stop-Transcript | Out-Null
    
  # Restart Explorer process
  Start-Job -ScriptBlock {
    Start-Sleep -Seconds 190
    Stop-Process -Name explorer -Force
    Start-Process explorer *> $null
  } *> $null
}

# Trigger uninstall of remaining Dell applications
$Remaining = Get-Package | Where-Object {
  $_.Name -like 'dell*' -and
  $_.Name -notlike '*firmware*' -and
  $_.Name -notlike '*WLAN*' -and
  $_.Name -notlike '*HID*' -and
  $_.Name -notlike '*Touch*'
}
  
foreach ($package in $Remaining) {
  Write-Host "Triggering uninstall for $($package.Name)" -NoNewline
  Uninstall-Package -Name $package.Name -Force *> $null
  Write-Host " done." -ForegroundColor "Green"
  Write-Log "Removed $($package.Name)"
}
    

# Download and run Bloatware Removal Utility
#Write-Host "Downloading Bloatware Removal Utility (BRU)..." -NoNewline
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/BRU.zip" -OutFile "c:\temp\BRU.zip" 
if (Test-Path $BRUZip -PathType Leaf) {
    # Extract the contents of BRU.zip to c:\BRU\
    #Write-Host " done." -ForegroundColor "Green"    
    #Write-Output "Download Complete!"
    #Write-Host "Extracting BRU..." -NoNewline
    Expand-Archive -Path "c:\temp\BRU.zip" -DestinationPath "c:\BRU\" -Force *> $null
    #Write-Host " done." -ForegroundColor "Green"
    Set-Location c:\bru\
    Stop-Transcript | Out-Null
        
    # Restart Explorer process
    Start-Job -ScriptBlock {
        Start-Sleep -Seconds 190
        Stop-Process -Name explorer -Force
        Start-Process explorer *> $null
    } *> $null
    
# Execute BRU with Spinner indicator
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -OutFile "c:\temp\BRU-Spinner.ps1" -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/BRU-Spinner.ps1" -UseBasicParsing
    & $BruSpinner
} catch {
    Write-Host "An error occurred during download: $_" -foregroundColor "Red"
}
        
    Start-Transcript -path c:\temp\baseline_transcript.txt -Append | Out-Null

    # Check if the Bloatware Removal Utility completed successfully
    $path = "C:\BRU"
    $filePattern = "Bloatware-Removal-*"

    # Get all files in the path that match the file pattern
    $files = Get-ChildItem -Path $path -Filter $filePattern

    if ($files.Count -gt 0) {
        Write-Output "Bloatware Removal Utility completed successfully." | Out-Null
        Write-Log "Bloatware Removal Utility Completed Successfully"
    } else {
        Write-Output "Bloatware Removal Utility failed." -foregroundColor "Red"
    }
} else {
    Write-Output "Download failed. File not found."
    Write-Log "Bloatware Removal Utility Download Failed" 

} else {
    Write-Warning "This script can only be run on a Dell system."
    Write-Log "Only Dell systems are eligible for this bloatware removal script."
} 

# Remove Microsoft OneDrive
try {
    $OneDriveProduct = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft OneDrive%')"
    if ($OneDriveProduct) {
        Write-Host "Removing Microsoft OneDrive (Personal)" -NoNewline
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
        Write-Host "OneDrive installation not found." -foregroundColor "Red"
    }
} catch {
    Write-Host "An error occurred: $_" -foregroundColor "Red"
}

# Remove Microsoft Teams Machine-Wide Installer
try {
    $TeamsMWI = Get-Package -Name 'Teams Machine*'
    if ($TeamsMWI) {
        Write-Host "Removing Microsoft Teams Machine-Wide Installer" -NoNewline
        Get-Package -Name 'Teams Machine*' | Uninstall-Package *> $null
        # Recheck if Teams Machine Wide Installer is uninstalled
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

# Install Google Chrome
$Chrome = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Google Chrome*" }

if ($Chrome) {
    Write-Host "Existing Google Chrome installation found." -ForegroundColor "Yellow"
} else {
    $FilePath = "c:\temp\ChromeSetup.exe"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        $ProgressPreference = 'Continue'
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ChromeSetup.exe"
        Write-Host "Downloading Google Chrome..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\ChromeSetup.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ChromeSetup.exe" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 1373744 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\ChromeSetup.exe to install Google Chrome silently
        & $chromeNotification
        Write-Host "Installing Google Chrome..." -NoNewline
        Start-Process -FilePath "C:\temp\Chromesetup.exe" -ArgumentList "/silent /install" -Wait
        & $clearPath
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Google Chrome installed successfully."
        & $chromeComplete
        Start-Sleep -Seconds 15
        & $clearPath
        
    }
    else {
        # Report download error
        & $chromeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Google Chrome download failed!"
        Start-Sleep -Seconds 10
        & $clearPath
        #Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}

# Acrobat Installation
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" }
Start-Sleep -Seconds 1
& $clearPath
if ($Acrobat) {
    Write-Host "Existing Acrobat Reader installation found." -ForegroundColor "Yellow"
} else {
    $FilePath = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRdrDC2300620360_en_US.exe"
        Write-Host "Downloading Adobe Acrobat Reader..." -NoNewline
        & $acrobatDownload
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
        & $clearPath
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 277900248 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        Write-Host "Installing Adobe Acrobat Reader..." -NoNewline
        & $acrobatNotification
        Start-Process -FilePath $FilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -Wait
        & $acrobatComplete
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Adobe Acrobat installed successfully."
        Start-Sleep -Seconds 2
        & $clearPath
    }
    else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Download failed. File size does not match."
        & $acrobatFailure
        Start-Sleep -Seconds 5
        & $clearPath
        Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}

# Install Office 2016
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft Office Professional Plus 2016*" }

if ($O365) {
    Write-Host "Existing Microsoft Office 2016 installation found." -ForegroundColor "Yellow"
} else {
    $FilePath = "C:\temp\O2k16pp.zip"
    if (-not (Test-Path $FilePath)) {
        # If not found, download it from the given URL
        $URL = "https://skgeneralstorage.blob.core.windows.net/o2k16pp/O2k16pp.zip"
        Write-Host "Downloading Microsoft Office 2016..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\O2k16pp.zip -Uri "https://skgeneralstorage.blob.core.windows.net/o2k16pp/O2k16pp.zip" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 757921802 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        & $officeNotice
        Expand-Archive -path c:\temp\O2k16pp.zip -DestinationPath 'c:\temp\' -Force
        Write-Host "Installing Microsoft Office 2016..." -NoNewline
        $OfficeInstaller = "C:\temp\Office2016_ProPlus\setup.exe"
        $OfficeArguments = "/adminfile .\SLaddInstallOffice.msp"
        Set-Location -path 'C:\temp\Office2016_ProPlus\'
        Start-Process -FilePath $OfficeInstaller -ArgumentList $OfficeArguments -Wait    
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Office 365 Installation Completed Successfully."
        & $clearPath
    }
    else {
        # Report download error
        & $officeFailure
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Office 2016 download failed!"
        Start-Sleep -Seconds 10
        & $clearPath
        #Remove-Item -Path $FilePath -force -ErrorAction SilentlyContinue
    }
}

# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }

if ($SWNE) {
    Write-Host "Existing NetExtender installation found." -ForegroundColor "Yellow"
} else {
    $NEFilePath = "c:\temp\NXSetupU-x64-10.2.337.exe"
    if (-not (Test-Path $NEFilePath)) {
        # If not found, download it from the given URL
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe"
        Write-Host "Downloading Sonicwall NetExtender..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\NXSetupU-x64-10.2.337.exe -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.2.337.exe" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $NEFilePath).Length
    $ExpectedSize = 4788816 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\NXSetupU-x64-10.2.337.exe /S to install NetExtender silently
        Write-Host "Installing Sonicwall NetExtender..." -NoNewline
        start-process -filepath "C:\temp\NXSetupU-x64-10.2.337.exe" /S -Wait
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Sonicwall NetExtender installed successfully."
    }
    else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Write-Log "Sonicwall NetExtender download failed!"
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue
    }
}

# Stop Procmon
taskkill /f /im procmon64.exe > $null

Write-Host "Starting Bitlocker Configuration..."

# Check if TPM module is enabled
$TPM = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled().Isenabled -eq 'True'} -ErrorAction SilentlyContinue

if ($TPM -eq $null) {
    Write-Host "TPM module not found on this machine! Terminating Bitlocker Configuration." -ForegroundColor "Red"
} else {
    Write-Host "TPM Module found on this machine"
    Write-Host "TPM Version: $($TPM.SpecVersion)"
    Write-Host "TPM Manufacturer: $($TPM.Manufacturer)"
    Write-Host "TPM Status: $($TPM.Status)"
}

# Check if Windows version and BitLocker-ready drive are present
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
    Write-Output "Generating Bitlocker recovery key"

    # Create the recovery key
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector

    # Add TPM key
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector
    sleep -Seconds 15 # This is to give sufficient time for the protectors to fully take effect.

    Write-Output "Enabling Encryption on drive C:\"

    # Enable Encryption
    Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -em aes256" -Verb runas -Wait

    # Get Recovery Key GUID
    $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).keyprotector | where {$_.Keyprotectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorID

    # Backup the Recovery to AD
    manage-bde.exe  -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID
    manage-bde -protectors C: -get > C:\temp\$env:computername-BitLocker.txt
    manage-bde c: -on

    $RecoveryKeyPW = (Get-BitLockerVolume -MountPoint $env:SystemDrive).keyprotector | where {$_.Keyprotectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty RecoveryPassword

    Write-Log "Bitlocker has been enabled on drive C:\."
    Write-Log "Bitlocker Recovery Key: $RecoveryKeyPW"
    Write-Output " "
    Write-Host "A reboot is required to complete encryption process!" 
    # Restarting the computer, to begin the encryption process
    # Restart-Computer
}

# Check for and install all available Windows update
Start-Sleep -Seconds 4
Write-Output "Starting Windows Update..."
& $updateNotice
Install-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
Import-Module PSWindowsUpdate
$updates = Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue
$TotalUpdates = $updates.Count
& $clearPath
Write-Output "$totalUpdates Windows updates are available."
if ($updates) {
    & $updateComplete
    Write-Log "Installed $($updates.Count) Windows updates"
    Start-Sleep -Seconds 30
    & $clearPath
} else {
    Write-Log "No additional Windows updates are available."
}

# Notify device is ready for Domain Join Operation
$NTFY1 = "& cmd.exe /c curl -d '%ComputerName% is ready to join the domain.' 172-233-196-225.ip.linodeusercontent.com/sslvpn"
Invoke-Expression -command $NTFY1 *> $null

Start-Sleep -Seconds 3
Write-Output " "
Write-Output "Starting Domain/Azure AD Join Function..."
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
Write-Output " "

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
        Add-Computer -DomainName $domain -Credential $cred 
        $domainJoinSuccessful = Test-ComputerSecureChannel
            if ($domainJoinSuccessful) {
                Write-Host "Domain join completed successfully."
                Write-Log "$env:COMPUTERNAME joined to $domain successfully"
            } else {
                Write-Host "Domain join failed." -ForegroundColor "Red"
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
        Write-Host "AzureAdJoined: $azureAdJoinedValue"
        Write-Log "$env:COMPUTERNAME joined to Azure AD."
    }
} else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter A or S."
    break
}

# Notify device Baseline is complete
$NTFY2 = "& cmd.exe /c curl -d '%ComputerName% Baseline is complete!' 172-233-196-225.ip.linodeusercontent.com/sslvpn"
Invoke-Expression -command $NTFY2 *> $null

# Final log entry
& $baselineComplete
Write-Log "Baseline configuration completed successfully."
Stop-Transcript

# Baseline temp file cleanup
Write-Host "Cleaning up temp files..." -NoNewline
Remove-Item -path c:\BRU -Recurse -Force
#Get-ChildItem -Path "C:\temp" -File | Where-Object { $_.Name -notlike "*bitlocker*" -and $_.Name -notlike "*baseline*" } | Remove-Item -Force
Write-Log "Baseline temp file cleanup completed successfully"
Start-Sleep -Seconds 1
Write-Host " done." -ForegroundColor "Green"    
Start-Sleep -seconds 2
Start-Process "appwiz.cpl"
Read-Host -Prompt "Press Enter to exit."
