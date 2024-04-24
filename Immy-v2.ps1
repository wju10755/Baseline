# Set default software name if not provided
if(!$SoftwareName) {
    $SoftwareName = "Microsoft 365 Home Premium"
}

# Get product release ID for the provided software name
$ProductReleaseId = Get-Office365ProductIDFromDisplayName $SoftwareName

# Function to get office installations
Function Get-OfficeInstallations {
    param (
        $ProductReleaseId
    )

    $InstalledPrograms = 'hklm:\Software\Microsoft\Windows\CurrentVersion\Uninstall','hklm:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | 
        Get-ChildItem -ErrorAction SilentlyContinue | 
        Where-Object { $null -eq $ProductReleaseid -or $_.PSPath -match $ProductReleaseId } | 
        Get-ItemProperty -Name DisplayName,DisplayIcon,InstallLocation,UninstallString -ErrorAction SilentlyContinue

    $OfficeInstallations = $InstalledPrograms | 
        Where-Object {
            ($_.DisplayName -like "*Microsoft 365*" -or 
             $_.DisplayName -like "Microsoft Office*" -or 
             $_.DisplayName -like "Microsoft OneNote*" -or 
             $_.DisplayName -like "Microsoft Visio *" -or 
             $_.DisplayName -like "Microsoft 365 Apps for*") -and 
            $_.DisplayName -notlike "*Project*" -and 
            $_.InstallLocation -notlike "" -and 
            $null -ne $_.DisplayIcon
        }

    foreach($OfficeInstallation in $OfficeInstallations) {
        Write-Host "Detected: $($OfficeInstallation.DisplayName) - $($OfficeInstallation.DisplayVersion) ($ExistingOfficeBitness)"
    }

    return $OfficeInstallations
}

# Get Office installations for the provided product release ID
$OfficeInstallations = Get-OfficeInstallations -ProductReleaseId $ProductReleaseId

# Check if any Office installations found, if not, throw an error
if(!$OfficeInstallations) {
    Throw "$SoftwareName (ProductId: $ProductReleaseId) not detected, cannot uninstall."
}

# Loop through each Office installation and initiate uninstall process
foreach($OfficeInstallation in $OfficeInstallations) {
    $UninstallParams = $OfficeInstallation.UninstallString.Replace("$($OfficeInstallation.DisplayIcon)", "").Replace("""""","")
    $UninstallParams += " /quiet" # Add silent uninstallation parameter
    Write-Host "Running ""$($OfficeInstallation.DisplayIcon)"" $UninstallParams"

    # Start uninstall process
    $SetupProcess = Start-Process $OfficeInstallation.DisplayIcon -ArgumentList $UninstallParams -PassThru #-Wait

    # Monitor uninstall process
    $processName = "OfficeClickToRun.exe"
    $argument = '(?:(productstoremove=.*?\s*$?)){1}$'
    $fullCommandLine = ""
    $ProcessFound = $false
    $ProcessChecks = 0
    $ProcessMaxChecks = 300
    $SecondsToWaitBetweenChecks = 1
    $ProcessMaxSecondsToCheck = $ProcessMaxChecks * $SecondsToWaitBetweenChecks

    Write-Host "Waiting up to $ProcessMaxSecondsToCheck seconds for $processName process to start..."
    do {
        $ProcessChecks++
        if($MatchingProcess) {
            $ProcessFound = $true
            $Process = Get-Process -Id $MatchingProcess.ProcessId
            $fullCommandLine = $MatchingProcess.CommandLine.Trim()
            Write-Host "Found $fullCommandLine"
            Write-Host "Waiting for exit..."
            $MaxMillisecondsToWaitForExit = 1000 * 7200
            $HasExited = $Process.WaitForExit($MaxMillisecondsToWaitForExit)
            if($Process.HasExited) {
                Write-Host "ProcessId $($Process.Id) exited."
            }
        }
        elseif(!$ProcessFound) {
            Start-Sleep -Seconds $SecondsToWaitBetweenChecks
            if($ProcessChecks -gt $ProcessMaxChecks) {
                Write-Host "Process $fullCommandLine was never seen running in the last $ProcessMaxSecondsToCheck seconds."
                break
            }
        }
        $MatchingProcess = Get-WmiObject win32_process | 
                            Where-Object { $_.Name -eq $processName -and ($null -eq $argument -or $_.CommandLine -match $argument) } | 
                            Select-Object -First 1
    } while($null -ne $MatchingProcess -or $ProcessFound -eq $false)

    $Process = $SetupProcess
    $Process.WaitForExit()
    ##Write-Host "Killing hung setup.exe (thanks Microsoft!)"
    ##taskkill /PID $Process.Id /F /T 2>&1 | Out-Null
    ##taskkill /PID "setup.exe" /F 2>&1 | Out-Null

    Write-Host "$SoftwareName Uninstall Exit Code:$($Process.ExitCode)"
    Write-Host ""
}
