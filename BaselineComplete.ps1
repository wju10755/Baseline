Clear-Host
Write-Host "MITS - Workstation Baseline Complete Verification"
Write-Output " "
# Instal Common Stuff 
$moduleName = "CommonStuff"

# Check if the module is installed
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    #Write-Host "Module '$moduleName' is not installed. Attempting to install..."

    # Attempt to install the module from the PowerShell Gallery
    # This requires administrative privileges
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        #Write-Host "Module '$moduleName' installed successfully."
    } catch {
        Write-Error "Failed to install module '$moduleName': $_"
        exit
    }
} else {
    #Write-Host "Module '$moduleName' is already installed."
}
try {
    Import-Module -Name $moduleName -ErrorAction Stop
    #Write-Host "Module '$moduleName' imported successfully."
} catch {
    Write-Error "Failed to import module '$moduleName': $_"
}

Import-Module CommonStuff
Write-Host "Installed Software Report:"
$Software = Get-InstalledSoftware | select DisplayName, DisplayVersion
$Software | ft -HideTableHeaders
$AzureADJoined = ((dsregcmd /status | select-string -Pattern "AzureAdJoined").Line).Trim()
$AzureADJoined
$DomainJoined = ((dsregcmd /status | select-string -Pattern "DomainJoined").Line).Trim()
$DomainJoined
Write-Output " "