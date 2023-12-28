cls
# Script: UpdateWindows.ps1
# Check if NuGet provider is installed
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    # Install NuGet provider
    Install-PackageProvider -Name NuGet -Force
}

# Ensure PSWindowsUpdate module is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -AllowClobber
}

# Import PSWindowsUpdate module
Import-Module PSWindowsUpdate

# Variables
$WUTemp = c:\temp\
$WULog = c:\temp\$env:COMPUTERNAME-Updates.log

# Create temp directory and baseline log
function Initialize-Environment {
    if (-not (Test-Path $WUTemp)) {
        New-Item -Path $WUTemp -ItemType Directory | Out-Null
    }
    if (-not (Test-Path $WULog)) {
        New-Item -Path $WULog -ItemType File | Out-Null
    }
}

# Baseline Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $WULog -Value "$(Get-Date) - $Message"
}


# Check for updates
Write-Host "Checking for updates..."
$availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
$ConsoleUpdates = $availableUpdates | Select-Object Title | ft -HideTableHeaders

# Display the total number of updates found
$totalUpdates = $availableUpdates.Count
Write-Host "Total Updates available: $totalUpdates"
Write-Log "Total Updates available: $totalUpdates"
Write-Log "$consoleUpdates"

Start-Sleep -Seconds 5
# Install updates
if ($totalUpdates -gt 0) {
    foreach ($update in $availableUpdates) {
        Write-Host "Installing update: $($update.Title)"
        Install-WindowsUpdate -KBArticleID $update.KBArticleID -AcceptAll -IgnoreReboot -AutoReboot:$false
    }
    Write-Host "Windows Update Complete!."
    Start-Sleep -Seconds 3
    Write-Host " "
} else {
    Write-Host "No updates available."
    Write-Host " "
}
