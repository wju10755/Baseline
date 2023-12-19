Start-Sleep -Seconds 4
$OfficeUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft 365 - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OfficeUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
        } 

Start-Sleep -Seconds 3

$OneNoteUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft OneNote - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OneNoteUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
        }  