Clear-Host
$ErrorActionPreference = 'SilentlyContinue'
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
$ErrorActionPreference = 'SilentlyContinue'
$WarningActionPreference = 'SilentlyContinue'
Start-Transcript -path c:\temp\baseline_transcript.txt
Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
#Write-Host "Starting workstation baseline..." -ForegroundColor "Yellow"=
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
[Console]::Write("Staging notifications (1,569,142 bytes)...")
$ProgressPreference = 'Continue'
$url = $config.PSNoticeURL
$filePath = $config.PSNoticeFile

if (-not (Test-Path -Path $filePath -PathType Leaf)) {
    Invoke-WebRequest -Uri $url -OutFile $filePath
    #Write-Output "File downloaded successfully."
} else {
    #Write-Output "File already exists."
}

if (Test-Path -Path $config.PSNoticeFile -PathType Leaf) {
    Expand-Archive -Path $config.PSNoticeFile -DestinationPath $config.PSNoticePath -Force
}


[Console]::ForegroundColor = [System.ConsoleColor]::Green
[Console]::Write(" done.")
[Console]::ResetColor() # Reset the color to default
[Console]::WriteLine() # Move to the next line

# Start Baseline Notification
& $config.StartBaseline | Out-Null
Write-Log "Automated workstation baseline has started"

# ConnectWise Automate Agent Installation
# Define file paths and names
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"

# Check if the installer file exists
if (-not (Test-Path $file)) {
    Write-Host "Downloading ConnectWise Automate Remote Agent..." -NoNewline
    Invoke-WebRequest -Uri $installerUri -OutFile $file -ErrorAction SilentlyContinue
}

# Check if the installer download was successful
if (Test-Path $file) {
    #Write-Host " done." -ForegroundColor Green
} else {
    Write-Host " failed!" -ForegroundColor Red
    Write-Log "The file [$file] download failed."
    exit
}

# Check if the LabTech agent is already installed
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    Write-Output "The LabTech agent is already installed."
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
    } else {
        Write-Host " failed!" -ForegroundColor Red
        Write-Log "ConnectWise Automate Agent installation failed!"
    }
}


# Identify device manufacturer and type
$computerSystem = Get-WmiObject Win32_ComputerSystem
$manufacturer = $computerSystem.Manufacturer
$deviceType = if ($computerSystem.PCSystemType -eq 2) { "Laptop" } else { "Desktop" }
Write-Host "Identifying device type: " -NoNewline
Start-Sleep -Seconds 2
Write-Host $deviceType -ForegroundColor "Cyan"
Write-Log "Manufacturer: $manufacturer, Device Type: $deviceType."
New-BurntToastNotification -Text "Identified device type: $manufacturer $deviceType" -AppLogo C:\temp\PSNotice\smallA.png
& $clearPath
Start-Sleep -Seconds 2

# Set power profile to 'Balanced'
Write-Host "Setting Power Profile..." -NoNewLine
Start-Sleep -Seconds 3
powercfg /S SCHEME_BALANCED
New-BurntToastNotification -Text "Power profile set to Balanced" -AppLogo "C:\temp\PSNotice\smallA.png"
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
New-BurntToastNotification -Text "Sleep and hibernation settings disabled" -AppLogo "c:\temp\PSNotice\smallA.png"
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
New-BurntToastNotification -Text "Fast startup disabled" -AppLogo "c:\temp\PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"
Start-Sleep -Seconds 5
& $clearPath

# Set power profile
Start-Sleep -Seconds 1
Write-Host "Configuring power profile..." -NoNewline
powercfg /SETACTIVE SCHEME_CURRENT
New-BurntToastNotification -Text "Power profile set to 'Balanced'" -AppLogo "c:\temp\PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"

# Set power button action to 'Shutdown'
Start-Sleep -Seconds 2
Write-Host "Configuring power button action to shutdown..." -NoNewline
powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /SETACTIVE SCHEME_CURRENT
New-BurntToastNotification -Text "Power button action set to 'Shutdown'" -AppLogo "c:\temp\PSNotice\smallA.png"
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
    New-BurntToastNotification -Text "Lid close action set to 'Do Nothing'" -AppLogo "c:\temp\PSNotice\smallA.png"
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
New-BurntToastNotification -Text "Default timezone set to 'EST'." -AppLogo "c:\temp\PSNotice\smallA.png"
Start-Sleep -Seconds 2
Write-Host " done." -ForegroundColor "Green"    
Start-Sleep -Seconds 5
& $clearPath

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 

# Enable system restore
Write-Host "Configuring System Restore..." -NoNewLine
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-Log "System restore enabled."
Write-Host " done." -ForegroundColor "Green"

# Create restore point
Write-Host "Creating System Restore Checkpoint..." -nonewline
Checkpoint-Computer -Description 'Baseline Settings' -RestorePointType 'MODIFY_SETTINGS'
$restorePoint = Get-ComputerRestorePoint | Sort-Object -Property "CreationTime" -Descending | Select-Object -First 1
if ($restorePoint -ne $null) {
    Write-Host " done." -ForegroundColor "Green"
} else {
    Write-Host "Failed to create restore point" -ForegroundColor "Red"
}
New-BurntToastNotification -Text "System restore is now enabled" -AppLogo "c:\temp\PSNotice\smallA.png"
Start-Sleep -Seconds 2
#Write-Host " done." -ForegroundColor "Green"
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


# Check if the system is manufactured by Dell
if ($manufacturer -eq "Dell Inc.") {
    # Set the URL and file path variables
    $SpinnerURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell-Spinner.ps1"
    $SpinnerFile = "c:\temp\Dell-Spinner.ps1"
    $DellSilentURL = "https://raw.githubusercontent.com/wju10755/Baseline/main/Dell_Silent_Uninstall.ps1"
    $DellSilentFile = "c:\temp\Dell_Silent_Uninstall.ps1"
 
    Invoke-WebRequest -Uri $SpinnerURL -OutFile $SpinnerFile -UseBasicParsing -ErrorAction Stop 
    Start-Sleep -seconds 1
    # Download Dell Silent Uninstall
    Invoke-WebRequest -Uri $DellSilentURL -OutFile $DellSilentFile -UseBasicParsing -ErrorAction Stop

    if (Test-Path -Path $SpinnerFile) {
    & $SpinnerFile
        }
    
} else {
    Write-Warning "This script can only be run on a Dell system."
    #Write-Log "Only Dell systems are eligible for this bloatware removal script."
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
        # Your Windows 11 specific code here
        # Download Win11Debloat.ps1
        $Win11DebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Win11Debloat.zip"
        $Win11DebloatFile = "c:\temp\Win11Debloat.zip"
        $Win11Debloat_SpinnerURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Win11Debloat_Spinner.ps1"
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        Invoke-WebRequest -Uri $Win11Debloat_SpinnerURL -OutFile $Win11Spinner -UseBasicParsing -ErrorAction Stop
        Start-Sleep -seconds 1
        if (Test-Path -Path $Win11DebloatFile) {
            Expand-Archive $Win11DebloatFile -DestinationPath c:\temp\Win11Debloat -Force
            & 'C:\temp\Win11Debloat\Win11Debloat\Win11Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent
        }
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
else {
    Write-Host "This script is intended to run only on Windows 11."
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
        Write-Host "Downloading Google Chrome (1,373,744 bytes)..." -NoNewline
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
        Write-Host "Downloading Adobe Acrobat Reader ( 277,900,248 bytes)..." -NoNewline
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
        Write-Host "Downloading Microsoft Office 2016 (757,921,585 bytes)..." -NoNewline
        Invoke-WebRequest -OutFile c:\temp\O2k16pp.zip -Uri "https://skgeneralstorage.blob.core.windows.net/o2k16pp/O2k16pp.zip" -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $FilePath).Length
    $ExpectedSize = 757921585 # in bytes
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
    #Write-Output "Recovery Key Password: $RecoveryKeyPW"
}

# Installing Windows Updates
& $config.UpdateNotice
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/update_windows.ps1" -OutFile "c:\temp\update_windows.ps1"
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows2.ps1"
    Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath
    & $config.ClearPath

} else {
    Write-host "Windows update module download failed" -ForegroundColor Red
}
& $config.UpdateComplete

# Remove Java Development Kit
$uninstallCommand = "MsiExec.exe"
$uninstallArguments = "/X{0232D1A9-B924-5BA2-8D5C-2C479AF9E842} /quiet /norestart"

try {
    # Start the uninstall process
    $process = Start-Process -FilePath $uninstallCommand -ArgumentList $uninstallArguments -Wait -NoNewWindow -PassThru

    # Check if the uninstallation was successful
    if ($process.ExitCode -eq 0) {
        Write-Log "Java Development Kit successfully uninstalled."
        Remove-Item -path "c:\temp\jdk-11.0.17_windows-x64_bin.exe" | Out-Null
    }
    else {
        Write-Log "Java Development Kit uninstallation failed. Exit Code: $($process.ExitCode)"
    }
}
catch {
    # Catch and display any exceptions
    Write-Log "An error occurred: $_"
}

# Check for and install all available Windows update
#Start-Sleep -Seconds 4
#Write-Output "Windows Update in progress..."
#& $updateNotice
#Install-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
#Import-Module PSWindowsUpdate
#$updates = Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue
#$TotalUpdates = $updates.Count
#& $clearPath
#Write-Output "$totalUpdates Windows updates are available."
#if ($updates) {
#    & $updateComplete
#    Write-Log "Installed $($updates.Count) Windows updates"
#    Start-Sleep -Seconds 30
#    & $clearPath
#} else {
#    Write-Log "No additional Windows updates are available."
#}


# Notify device is ready for Domain Join Operation
$NTFY1 = "& cmd.exe /c curl -d '%ComputerName% is ready to join the domain.' 172-233-196-225.ip.linodeusercontent.com/sslvpn"
Invoke-Expression -command $NTFY1 *> $null

Start-Sleep -Seconds 3
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
Start-Sleep -seconds 1
Start-Process "appwiz.cpl"
Read-Host -Prompt "Press Enter to exit."
