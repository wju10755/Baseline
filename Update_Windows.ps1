# Script: UpdateWindows.ps1

# Ensure PSWindowsUpdate module is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
}

# Import PSWindowsUpdate module
Import-Module PSWindowsUpdate

# Check for updates
Write-Host "Checking for Windows updates..."
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
    Write-Host "Updates installation complete."
    Start-Sleep -Seconds 3
} else {
    Write-Host "No updates are available."
}
