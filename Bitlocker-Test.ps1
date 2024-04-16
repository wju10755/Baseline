# Check Bitlocker Compatibility
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {

    # Check if Bitlocker is already configured on C:
    $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    if ($BitLockerStatus.ProtectionStatus -eq 'On') {
        # Bitlocker is already configured
        Write-Host -ForegroundColor Red "Bitlocker is already configured on drive $env:SystemDrive`n"
        $userResponse = Read-Host "Do you want to skip configuring Bitlocker? (yes/no)"
        Write-Host " "

        if ($userResponse -like 'n') {
            # Remove all protectors from C:
            manage-bde c: -off *> $null
            $process = Start-Process -FilePath "manage-bde" -ArgumentList "C: -off" -PassThru -Wait

            # Check if the command was successful
            if ($process.ExitCode -eq 0) {
                Write-Host "Decryption now in progress."
            } else {
                Write-Host "Failed to start decryption."
            }   
            $BitLockerVolume = Get-BitLockerVolume -MountPoint "C:" | Out-Null
            $Protectors = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectortype -eq 'Tpm' -or $_.KeyProtectortype -eq 'NumericalPassword' }
            foreach ($Protector in $Protectors) {
                Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $Protector.KeyProtectorId | Out-Null
            }
            Write-Host " "
            # Monitor the "Percentage Encrypted" value until it reaches 0.0%
            for (;;) {
                $status = manage-bde -status C:
                $percentageEncrypted = ($status | Select-String -Pattern "Percentage Encrypted:.*").ToString().Split(":")[1].Trim()

                # Clear the current line
                Write-Host "`rCurrent decryption progress: $percentageEncrypted" -NoNewline

                if ($percentageEncrypted -eq "0.0%") {
                    break
                }

                Start-Sleep -Seconds 1
            }
            Write-Host " "
            Write-Host "`nDecryption of $env:SystemDrive is complete."
            Write-Host " "

            # Wait 5 seconds
            Start-Sleep -Seconds 5
            Write-Host "Configuring Bitlocker Disk Encryption..."
            Write-Host " "
            # Configure Bitlocker on C:
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector | Out-Null
            Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait *> $null
            Write-Host " "
            # Verify volume key protector exists
            $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive

            # Check if a protector exists
            if ($BitLockerVolume.KeyProtector) {
                Write-Host "Bitlocker drive encryption configured successfully."
            } else {
                Write-Host "Bitlocker drive encryption is not configured."
            }     
        }
    } else {
        Write-Host "Configuring Bitlocker Disk Encryption..."
        Write-Host " "
        # Create the recovery key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null

        # Add TPM key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector | Out-Null
        Start-Sleep -Seconds 15 # Wait for the protectors to take effect

        # Enable Encryption
        Start-Process 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait *> $null
        Write-Host " "

        # Verify volume key protector exists
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive

        # Check if a protector exists
        if ($BitLockerVolume.KeyProtector) {
            Write-Host "Bitlocker drive encryption configured successfully!`n"
        } else {
            Write-Host -ForegroundColor Red "Bitlocker drive encryption is not configured!"
        }
    }
} else {
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}
