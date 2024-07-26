$LogFile = "c:\temp\baselinetest.log"

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


# Baseline Operations Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Message"
}

# Check PC System Type
$pcSystemType = (Get-WmiObject -Class Win32_ComputerSystem).PCSystemType

if ($pcSystemType -eq 2) {
    # GUID for the currently active power scheme
    Write-Delayed "Configuring Mobile Device Power Profile..." -NewLine:$false
    Start-Sleep -Seconds 2  
    # Disable sleep and hibernation modes
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
    Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
    # Set the power button action to 'Shutdown' (00000400)
    Start-Process -FilePath "powercfg" -ArgumentList "/SETACVALUEINDEX $activeScheme SUB_BUTTONS PBUTTONACTION 00000400" -NoNewWindow -Wait
    Start-Process -FilePath "powercfg" -ArgumentList "/SETDCVALUEINDEX $activeScheme SUB_BUTTONS PBUTTONACTION 00000400" -NoNewWindow -Wait
    Start-Sleep -Seconds 2
    Write-Log "Power button action set to 'Shutdown'."
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine() 
    Write-Delayed "Setting 'Do Nothing' lid close action..." -NewLine:$false
    Write-Log "'Lid close action' set to Do Nothing. (Laptop)"
    Start-Sleep -Seconds 2
    # Set the lid close action to 'Do Nothing' (00000000)
    powercfg /SETACVALUEINDEX $activeScheme SUB_BUTTONS LIDACTION 00000000
    powercfg /SETDCVALUEINDEX $activeScheme SUB_BUTTONS LIDACTION 00000000
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    # Set the sleep setting to 2 hours (7200 seconds) on battery
    Write-Delayed "Setting 'Setting Standby Idle time to 2 hours on battery..." -NewLine:$false
    powercfg /SETDCVALUEINDEX $activeScheme SUB_SLEEP STANDBYIDLE 7200
    Write-Delayed "Setting Standby Idle time to 2 hours on AC power..." -NewLine:$false
    # Set to never sleep when plugged in (0 seconds)
    powercfg /SETACVALUEINDEX $activeScheme SUB_SLEEP STANDBYIDLE 0 
    Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Delayed "Activating Power Scheme..." -NewLine:$false
    # Apply the changes
    powercfg /S $activeScheme
}

if ($pcSystemType -eq 1 -or $pcSystemType -eq 3 ) {
    Write-Delayed "Configuring Desktop/Workstation Device Power Profile..." -NewLine:$false
    Start-Sleep -Seconds 2  
    # Disable sleep and hibernation modes
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
    Start-Sleep -Seconds 2
    Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
    Start-Process -FilePath "powercfg" -ArgumentList "/SETACVALUEINDEX $activeScheme SUB_BUTTONS PBUTTONACTION 00000400" -NoNewWindow -Wait
    Write-Log "Power button action set to 'Shutdown'."
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Delayed "Setting Standby Idle time to 2 hours on AC power..." -NewLine:$false
    # Set to never sleep when plugged in (0 seconds)
    powercfg /SETACVALUEINDEX $activeScheme SUB_SLEEP STANDBYIDLE 0 
    Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Delayed "Activating Power Scheme..." -NewLine:$false
    # Apply the changes
    powercfg /S $activeScheme
} else {
    Write-Output "No action needed for system type $pcSystemType."
}