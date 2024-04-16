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

                # Prompt for the domain controller name
                $domainController = Read-Host "Enter the domain controller name"

                # Issue a djoin command to generate the win10blob.txt file
                $username = Read-Host "Enter the admin username for the domain join operation"
                $password = Read-Host "Enter the password for the domain join operation" -AsSecureString
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                $domain = Read-Host "Enter the domain name for the domain join operation"

                # Use the djoin command to generate the win10blob.txt file
                try {
                    $djoinCommand = "djoin /provision /domain $domain /machine `"$env:COMPUTERNAME`" /savefile win10blob.txt"
                    # Start a new PowerShell session on the domain controller and run the djoin command
                    Invoke-Command -ComputerName $domainController -Credential $cred -ScriptBlock {
                        param($djoinCommand)
                        cmd.exe /c $djoinCommand
                    } -ArgumentList $djoinCommand
                    Write-Host "Djoin command executed successfully."

                    # Transfer the win10blob.txt file to the machine running the script
                    $destinationPath = "C:\temp\win10blob.txt"
                    Copy-Item -Path "win10blob.txt" -Destination $destinationPath
                    Write-Host "win10blob.txt file transferred successfully to $destinationPath"

                    # Run the djoin /requestodj /loadfile command
                    $djoinRequestCommand = "djoin /requestodj /loadfile win10blob.txt /windowspath %SystemRoot% /localos"
                    Invoke-Command -ComputerName $domainController -Credential $cred -ScriptBlock {
                        param($djoinRequestCommand)
                        cmd.exe /c $djoinRequestCommand
                    } -ArgumentList $djoinRequestCommand
                    Write-Host "Djoin /requestodj /loadfile command executed successfully."
                } catch {
                    Write-Host "Failed to execute the djoin command."
                }
            } else {
                Write-Host "The 'Sonicwall NetExtender' adapter is not connected to the SSLVPN."
            }
            Write-Output " "
        } else {
            [Console]::Write("`n")
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Host "SonicWall NetExtender not found"
            break
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
        Write-Host "Domain join operation completed successfully."
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