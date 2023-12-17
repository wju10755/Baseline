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

# Check for updates
Write-Host "Checking for updates..."
$availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot

# Display the total number of updates found
$totalUpdates = $availableUpdates.Count
Write-Host "Total Updates available: $totalUpdates"
Start-Sleep -Seconds 5
# Install updates
if ($totalUpdates -gt 0) {
    foreach ($update in $availableUpdates) {
        Write-Host "Installing update: $($update.Title)"
        Install-WindowsUpdate -KBArticleID $update.KBArticleID -AcceptAll -IgnoreReboot -AutoReboot:$false
    }
    Write-Host "Windows Update Complete!."
    Start-Sleep -Seconds 3
} else {
    Write-Host "No updates available."
}
