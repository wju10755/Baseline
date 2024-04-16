function Connect-VPN {
    if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
        Write-Host "NetExtender detected successfully, starting connection..."
        Start-Process C:\temp\ssl-vpn.bat
        Start-Sleep -Seconds 5
        $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"
        if ($connectionProfile) {
            Write-Host "The 'Sonicwall NetExtender' adapter is connected to the SSLVPN."
        } else {
            Write-Host "The 'Sonicwall NetExtender' adapter is not connected to the SSLVPN."
        }
    } else {
        Write-Host "SonicWall NetExtender not found" -ForegroundColor Red
    }
}

[Console]::Write("`b`bStarting Domain/Azure AD Join Function...`n")
Write-Output " "

$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
} catch {
    Write-Host "Failed to download SSL VPN installer: $_" -ForegroundColor Red
    exit
}
$ProgressPreference = 'Continue'

$choice = Read-Host "Do you want to connect to SSL VPN? (Y/N)"
switch ($choice) {
    "Y" { Connect-VPN }
    "N" { Write-Host "Skipping VPN Connection Setup..." }
    default { Write-Host "Invalid choice. Please enter Y or N." }
}

$choice = Read-Host "Do you want to join a domain or Azure AD? (A for Azure AD, S for domain)"
switch ($choice) {
    "S" {
        $username = Read-Host "Enter the username for the domain join operation"
        $password = Read-Host "Enter the password for the domain join operation" -AsSecureString
        $cred = New-Object System.Management.Automation.PSCredential($username, $password)
        $domain = Read-Host "Enter the domain name for the domain join operation"
        try {
            Add-Computer -DomainName $domain -Credential $cred 
            Write-Host "Domain join operation completed successfully."
        } catch {
            Write-Host "Failed to join the domain."
        }
    }
    "A" {
        Write-Host "Starting Azure AD Join operation using Work or School account..."
        Start-Process "ms-settings:workplace"
        Start-Sleep -Seconds 3
        $output = dsregcmd /status | Out-String
        $azureAdJoined = $output -match 'AzureAdJoined\s+:\s+(YES|NO)' | Out-Null
        $azureAdJoinedValue = if($matches) { $matches[1] } else { "Not Found" }
        Write-Host "AzureADJoined: $azureAdJoinedValue"
    }
    default { Write-Host "Invalid choice. Please enter A or S." }
}