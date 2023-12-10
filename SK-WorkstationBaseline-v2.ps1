# Requirement: Run As Administrator
Clear-Host

# Central Configuration
$config = @{
    PSNoticeUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/psnotice.zip"
    NoSnoozeUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NoSnooze.zip"
    TempFolder           = "C:\temp"
    LogFile              = "C:\temp\baseline.log"
    NoSnooze             = "c:\temp\nosnooze.ps1"
    NoSnoozeZip          = "c:\temp\nosnooze.zip"
    JDKInstallerPath     = "C:\temp\jdk-11.0.17_windows-x64_bin.exe"
    JDKVersion           = "11.0.17"
    JDKArguments         = "/s"
    PSNoticePath         = "c:\temp\PSNotice"
    PSNoticeFile         = "c:\temp\psnotice.zip"
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


[Console]::Write("Staging Anti-Snooze ...")
try {
    Invoke-WebRequest -Uri $config.NoSnoozeUrl -OutFile $config.NoSnoozeZip -ErrorAction Stop
    Expand-Archive -Path $config.NoSnoozeZip -DestinationPath $config.TempFolder -Force -ErrorAction Stop
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
