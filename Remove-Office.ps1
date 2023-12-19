$OfficeUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft 365 - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OfficeUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Write-Host "This is where the Microsoft 365 uninstall will be triggered"
            Start-Sleep -seconds 10
            #Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
        } 

Start-Sleep -Seconds 3

$OneNoteUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft OneNote - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OneNoteUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Write-Host "This is where the Microsoft OneNote uninstall will be triggered"
            Start-Sleep -seconds 10 
            #Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
        }  