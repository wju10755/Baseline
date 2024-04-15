Write-Output " "
[Console]::Write("`b`bStarting Domain/Azure AD Join Function...`n")
Write-Output " "
Start-Sleep -Seconds 1
#$SDJF = "Starting Domain/Azure AD Join Function..."
#foreach ($Char in $SDJF.ToCharArray()) {
#    [Console]::Write("$Char")
#    Start-Sleep -Milliseconds 30    
#    }

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
$ProgressPreference = 'Continue'
# Prompt the user to connect to SSL VPN
$SDJF = "Do you want to connect to SSL VPN? Enter Y or N?`n"
foreach ($Char in $SDJF.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }
$choice = Read-Host

if ($choice -eq "Y" -or $choice -eq "N") {
    if ($choice -eq "Y") {
                
        if (Test-Path 'C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe') {
            [Console]::Write("NetExtender detected successfully, starting connection...")
            start C:\temp\ssl-vpn.bat
            Start-Sleep -Seconds 5
            # Get the network connection profile for the specific network adapter
            connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"

            # Check if the network adapter is connected to a network
            if ($connectionProfile) {
                Write-Host "The 'Sonicwall NetExtender' adapter is connected to the SSLVPN."
            } else {
                Write-Host "The 'Sonicwall NetExtender' adapter is not connected to the SSLVPN."
            }
            Write-Output " "
            Read-Host -Prompt "Press Enter once connected to SSL VPN to continue."
        } else {
            [Console]::Write("`n")
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            $NENF = "SonicWall NetExtender not found"
            foreach ($Char in $NENF.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
            [Console]::ResetColor()
            [Console]::WriteLine()   
            goto continue_script
        }
    } else {
        # Skip the VPN connection setup
        #[Console]::Write("`n")
        $SVPNS = "Skipping VPN Connection Setup..."
        foreach ($Char in $SVPNS.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
            [Console]::ResetColor()
            [Console]::WriteLine()
            #[Console]::Write("`n")

    }
} else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter Y or N."
    Write-Log "Invalid response received."
    goto continue_script
}

:continue_script
# Prompt the user to choose between standard domain join or Azure AD join
[Console]::Write("`n")
$JoinOp = "Do you want to perform a standard domain join (S) or join Azure AD (A)? Enter S or A?`n"
foreach ($Char in $JoinOp.ToCharArray()) {
    [Console]::Write("$Char")
    Start-Sleep -Milliseconds 30    
    }

$choice = Read-Host

# Validate the user input
if ($choice -eq "A" -or $choice -eq "S") {

    # Perform the join operation based on the user choice
    if ($choice -eq "S") {
        # Get the domain name from the user
        $cred = Get-Credential -Message "Enter the credentials for the domain join operation"
        $domain = Read-Host -Prompt "Enter the domain name to join"

        # Join the system to the domain using the credentials
        $joinOutput = Add-Computer -DomainName $domain -Credential $cred 
        $domainJoinSuccessful = Test-ComputerSecureChannel
        # Check if the output contains the warning message
        if ($joinOutput -notlike "*Warning: The changes will take effect after you restart the computer*") {
            Write-Host " "
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            $DJCS = "Domain join operation completed successfully."
            foreach ($Char in $DJCS.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
                [Console]::ResetColor()
                [Console]::WriteLine()
            Write-Log "$env:COMPUTERNAME joined to $domain successfully"
        } else {
            Write-Host " "
            [Console]::ForegroundColor = [System.ConsoleColor]::Yellow
            $DJCSRR = "Domain join operation completed successfully, restart is required!"
            foreach ($Char in $DJCSRR.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30    
                }
                [Console]::ResetColor()
                [Console]::WriteLine()
            Write-Log "$env:COMPUTERNAME joined to $domain but requires a restart."
        }
    } else {
        # Join the system to Azure AD using Work or school account
        $SAADJ = "Starting Azure AD Join operation using Work or School account..."
        foreach ($Char in $SAADJ.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
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
        Write-Host " "
        $AADJV = "AzureADJoined: $azureADJoinedValue"
        foreach ($Char in $AADJV.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        Write-Log "$env:COMPUTERNAME joined to Azure AD."
    }
    } else {
    # Display an error message if the user input is invalid
    Write-Error "Invalid choice. Please enter A or S."
    Write-Log "Invalid domain join response received."
    #break
}
