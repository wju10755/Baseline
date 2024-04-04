    # Trigger uninstall of all pre-installed versions of Microsoft 365 Apps
    $OfficeUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft 365 - *"} | Select UninstallString).UninstallString

    # Capture the start time
    $startTime = Get-Date
    #Write-Host "Uninstall Started: "
    ForEach ($UninstallString in $OfficeUninstallStrings) {
        $UninstallEXE = ($UninstallString -split '"')[1]
        $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
        Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
    }

    # Capture the end time
    $endTime = Get-Date

    # Calculate the elapsed time
    $elapsedTime = $endTime - $startTime

    # Output the elapsed time in HH:mm:ss format
    Write-Host "Total Uninstall Time: $($elapsedTime.ToString('hh\:mm\:ss'))"