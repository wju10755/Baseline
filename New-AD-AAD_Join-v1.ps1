[Console]::Write("`b`bStarting Domain/Azure AD Join Function...`n")
Write-Output " "
Start-Sleep -Seconds 1

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
$ProgressPreference = 'Continue'

# Ask the user if they want to connect to SSL VPN
$choice = Read-Host "Do you want to connect to SSL VPN? (Y/N)"

if ($choice -eq "Y" -or $choice -eq "N") {
    if ($choice -eq "Y") {
        if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
            [Console]::Write("NetExtender detected successfully, starting connection...")
            start C:\temp\ssl-vpn.bat
            Start-Sleep -Seconds 5
            # Get the network connection profile for the specific network adapter
            $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"

            # Check if the network adapter is connected to a network
            if ($connectionProfile) {
                Write-Host "The 'Sonicwall NetExtender' adapter is connected to the SSLVPN."
            } else {
                Write-Host "The 'Sonicwall NetExtender' adapter is not connected to the SSLVPN."
            }
            Write-Output " "
        } else {
            [Console]::Write("`n")
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Host "SonicWall NetExtender not found"
            [Console]::ResetColor()
            [Console]::WriteLine()   
        }
    } else {
        Write-Host "Skipping VPN Connection Setup..."
    }
} else {
    Write-Host "Invalid choice. Please enter Y or N."
}

# Ask the user if they want to join a domain or Azure AD
$choice = Read-Host "Do you want to join a domain or Azure AD? (A for Azure AD, S for domain)"

# Validate the user input
if ($choice -eq "A" -or $choice -eq "S") {
    # Perform the join operation based on the user choice
    if ($choice -eq "S") {
        # Ask the user for credentials and domain name for the domain join operation
        $username = Read-Host "Enter the username for the domain join operation"
        $password = Read-Host "Enter the password for the domain join operation" -AsSecureString
        $cred = New-Object System.Management.Automation.PSCredential($username, $password)
        $domain = Read-Host "Enter the domain name for the domain join operation"

        # Join the system to the domain using the credentials
        try {
            Add-Computer -DomainName $domain -Credential $cred 
            Write-Host "Domain join operation completed successfully."
        } catch {
            Write-Host "Failed to join the domain."
        }
    } else {
        Write-Host "Starting Azure AD Join operation using Work or School account..."
        Start-Sleep -Seconds 2
        Start-Process "ms-settings:workplace"
        Start-Sleep -Seconds 3
        # Run dsregcmd /status and capture its output
        $output = dsregcmd /status | Out-String

        # Extract the AzureAdJoined value
        $azureAdJoined = $output -match 'AzureAdJoined\s+:\s+(YES|NO)' | Out-Null
        $azureAdJoinedValue = if($matches) { $matches[1] } else { "Not Found" }
        Start-Sleep -Seconds 3
        # Display the extracted value
        Write-Host "AzureADJoined: $azureAdJoinedValue"
    }
} else {
    Write-Host "Invalid choice. Please enter A or S."
}