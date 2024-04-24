if(!$SoftwareName) {
    $SoftwareName = "Microsoft 365 Home Premium"
}

$ProductReleaseId = Get-Office365ProductIDFromDisplayName $SoftwareName

Invoke-Command -Timeout 1800 {
    Function Get-OfficeInstallations
    {
        param(
            $ProductReleaseId
        )
        $InstalledPrograms = 'hklm:\Software\Microsoft\Windows\CurrentVersion\Uninstall','hklm:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ChildItem -ErrorAction SilentlyContinue | ?{$null -eq $ProductReleaseid -or $_.PSPath -match "$ProductReleaseId"} | Get-ItemProperty -Name DisplayName,DisplayIcon,InstallLocation,UninstallString -ErrorAction SilentlyContinue
        $OfficeInstallations = $InstalledPrograms | ?{($_.DisplayName -like "*Microsoft 365*" -or $_.DisplayName -like "Microsoft Office*" -or $_.DisplayName -like "Microsoft OneNote*" -or $_.DisplayName -like "Microsoft Visio *" -or $_.DisplayName -like "Microsoft 365 Apps for*") -and $_.DisplayName -notlike "*Project*" -and $_.InstallLocation -notlike "" -and $null -ne $_.DisplayIcon}
        foreach($OfficeInstallation in $OfficeInstallations)
        {
            Write-Host "Detected: $($OfficeInstallation.DisplayName) - $($OfficeInstallation.DisplayVersion) ($ExistingOfficeBitness)"
        }
        return $OfficeInstallations
    }
    $OfficeInstallations = Get-OfficeInstallations $Using:ProductReleaseId
    if(!$OfficeInstallations) {
        Throw "$SoftwareName (ProductId: $($Using:ProductReleaseId)) not detected, cannot uninstall."
    }
    foreach($OfficeInstallation in $OfficeInstallations) {
        $UninstallParams = $OfficeInstallation.UninstallString.Replace("$($OfficeInstallation.DisplayIcon)","").Replace("""""","")
        Write-Host "Running ""$($OfficeInstallation.DisplayIcon)"" $UninstallParams"
        $SetupProcess = Start-Process $OfficeInstallation.DisplayIcon -ArgumentList $UninstallParams -PassThru #-Wait

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
            $MatchingProcess = gcim win32_process | ?{$_.Name -eq $processName -and ($null -eq $argument -or $_.CommandLine -match $argument)} | Select -First 1
        } while($null -ne $MatchingProcess -or $ProcessFound -eq $false)

        $Process = $SetupProcess
        $Process.WaitForExit()
        ##Write-Host "Killing hung setup.exe (thanks Microsoft!)"
        ##taskkill /PID $Process.Id /F /T 2>&1 | Out-Null
        ##taskkill /PID "setup.exe" /F 2>&1 | Out-Null

        Write-Host "$SoftwareName Uninstall Exit Code:$($Process.ExitCode)"
        Write-Host ""
    }

}

#return #DR 20230712, old script below not working for uninstalls. Above was successfully tested with Microsoft 365 Home Premium which was showing in add/remove as "Microsoft 365 - en-us"
#####################THE BELOW SCRIPT WAS A SYSTEM SCRIPT, NOT A METASCRIPT.



Function Get-Office365ProductIDFromDisplayName
{
    param([string]$DisplayName)
    $SoftwareName = $DisplayName
    $ProductID = $null
    if($SoftwareName -like "Microsoft 365 Apps for enterprise*")
    {
        $ProductID = 'O365ProPlusRetail'
    }
    elseif($SoftwareName -like "Microsoft 365 Apps for business*")
    {
        $ProductID = 'O365BusinessRetail'
    }
    elseif($SoftwareName -like "Office 2019 Standard")
    {
        $ProductID = 'Standard2019Volume'
    }
    elseif($SoftwareName -like "Office 2019 ProPlus")
    {
        $ProductID = 'ProPlus2019Volume'
    }
    elseif($SoftwareName -like "Microsoft Visio 365*")
    {
        $ProductID = 'VisioProRetail'
    }
    elseif($SoftwareName -like "Microsoft Project 365*")
    {
        $ProductID = 'ProjectProRetail'
    }
    elseif($SoftwareName -like "Office 2016 Click to Run Volume License")
    {
        $ProductID = 'ProfessionalRetail'
    }
    elseif($SoftwareName -like "Office 2021 ProPlus*")
    {
        $ProductID = 'ProPlus2021Volume'
    }
elseif($SoftwareName -like "Microsoft 365 Home Premium")
    {
        $ProductID = 'O365HomePremRetail'
    }
    else
    {
        Write-Host "Unable to find ProductID for $SoftwareName"        
    }
    return $ProductID
}



$ProductID = Get-Office365ProductIDFromDisplayName $SoftwareName
if($null -eq $ProductID)
{
    return
}

if($ExclusiveProductIDs -contains $ProductID)
{
    $ProductIDsToRemove = $ExclusiveProductIDs | ?{$_ -ne $ProductID}
}

if($SpecificVersion)
{
    $Version = $SpecificVersion
}
else
{
    $Version = $DisplayVersion
}




$AppxProvisioningPackageToRemove = Get-AppxProvisionedPackage -online | ?{$_.DisplayName -like "Microsoft.Office.Desktop"}
if($AppxProvisioningPackageToRemove)
{
    Write-Host "Removing OEM Microsoft.Office.Desktop Provisioned Package"
    try {
        $AppxProvisioningPackageToRemove | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "An error ocurred removing Microsoft.Office.Desktop"
    }
}
### Check for 32/64 bit OS and set MSO version accordingly
$ExistingOfficeBitness = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration -Name Platform -ErrorAction SilentlyContinue | select -ExpandProperty Platform
Write-Host "Existing Office Bitness: $ExistingOfficeBitness"
$MigrateArch = $false
if($ProductID -notlike "*Visio*" -and $ProductID -notlike "*Project*")
{
    $ArcVersion = "32"
    $DesiredOfficeBitness = "x86"
    if($Platform)
    {
        if(!$ExistingOfficeBitness)
        {
            # Fresh install
            Write-Host "No Existing Office"
            if($Platform -like "*64*")
            {
                $ArcVersion = "64"
                $DesiredOfficeBitness = "x64"
            }
            else
            {
                $ArcVersion = "32"
                $DesiredOfficeBitness = "x86"
            }
        }
        else
        {
            # Already has Office
            if(($Platform -like "*Keep Existing*" -and $ExistingOfficeBitness -like "*64*") -or ($Platform -notlike "*Keep Existing*" -and $Platform -like "*64*"))
            {
                $ArcVersion = "64"
                $DesiredOfficeBitness = "x64"   
            }
            else
            {
                $ArcVersion = "32"
                $DesiredOfficeBitness = "x86"
            }
        }
        Write-Host "Existing Office bitness: $ExistingOfficeBitness, Desired Office Bitness: $DesiredOfficeBitness"
        if($ExistingOfficeBitness -notlike $DesiredOfficeBitness)
        {
            $MigrateArch = $true
        }
    }
    else
    {
        $MigrateArch = $true
    }
    $MigrateArchXML = "OfficeClientEdition=`"$ArcVersion`""
    if($MigrateArch -eq $true)
    {
        $MigrateArchXML += " MigrateArch=`"$MigrateArch`""
    }
}


if($SoftwareName -like "Microsoft 365 Apps for*" -or $SoftwareName -like "Office 2019*" -or $SoftwareName -like "Office 2016*" -or $SoftwareName -like "Office 2021*")
{
    Function Get-OfficeInstallations
    {
        $InstalledPrograms = 'hklm:\Software\Microsoft\Windows\CurrentVersion\Uninstall','hklm:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ChildItem -ErrorAction SilentlyContinue | Get-ItemProperty -Name DisplayName,DisplayIcon,InstallLocation,UninstallString -ErrorAction SilentlyContinue
        $OfficeInstallations = $InstalledPrograms | ?{($_.DisplayName -like "Microsoft Office*" -or $_.DisplayName -like "Microsoft Visio *" -or $_.DisplayName -like "Microsoft 365 Apps for*") -and $_.DisplayName -notlike "*Project*" -and $_.InstallLocation -notlike "" -and $_.DisplayIcon -ne $null}
        foreach($OfficeInstallation in $OfficeInstallations)
        {
            Write-Host "- $($OfficeInstallation.DisplayName) - $($OfficeInstallation.DisplayVersion) ($ExistingOfficeBitness)"
        }
        return $OfficeInstallations
    }
    $OfficeInstallations = Get-OfficeInstallations
    $OfficeInstallationCount = ($OfficeInstallations | measure).Count
    Write-Host "Detected $OfficeInstallationCount existing Office installations"
    $Attempt = 0
    while($OfficeInstallations -and $OfficeInstallationCount -gt 0 -and $Attempt -lt 3)
    {
        if(($ExistingOfficeBitness -ne $DesiredOfficeBitness))
        {
            # Remove ALL office products if bitness doesn't match
            Write-Host "32/64 Mismatch: Existing: $ExistingOfficeBitness Desired: $DesiredOfficeBitness"
            $IncompatibleMicrosoftAccessPackage = $InstalledPrograms | ?{ $_.DisplayName -like "Microsoft Access database engine*" }
            if($IncompatibleMicrosoftAccessPackage)
            {
                Write-Host "Removing Microsoft Access database engine"
                Start-Process -Wait cmd -ArgumentList "/c $($IncompatibleMicrosoftAccessPackage.UninstallString)" 
            }
            $OfficeProgramsToRemove = $OfficeInstallations
            $MigrateArch = $true
        }
        else
        {
            # Preserve the program we are attempting to install
            $OfficeProgramsToPreserve = $OfficeInstallations | ?{$_.UninstallString -like "*$ProductID*"} 
            if($OfficeProgramsToPreserve)
            {
                Write-Host "Preserving the following Office installations:"
                foreach($OfficeProgram in $OfficeProgramsToPreserve)
                {
                    Write-Host "$($OfficeProgram.DisplayName) - $($OfficeProgram.DisplayVersion)"
                }
            }
            $OfficeProgramsToRemove = $OfficeInstallations | ?{$OfficeProgramsToPreserve -notcontains $_}    
        }
        $UseOffScrub = $true
        if($OfficeProgramsToRemove)
        {
            Write-Host "Removing $(($OfficeProgramsToRemove | measure | select -expand Count)) Office Programs"
            $Results = $OfficeProgramsToRemove | %{
                $RetVal = [ordered]@{}
                $OfficeProgram = $_
                $UninstallString = $null
                Write-Host "Removing $($OfficeProgram.DisplayName)"
                $RetVal.Name = $OfficeProgram.DisplayName
                $RetVal.Version = $OfficeProgram.DisplayVersion
                if($OfficeProgram.UninstallString -like "*version*=15.*" -or $OfficeProgram.UninstallString -like "*version*=16.*" -or $OfficeProgram.UninstallString -like "*OfficeClickToRun.exe*")
                {
                    $RetVal.InstallType = "Click To Run"
                    $UninstallXML = @"
            <Configuration><Remove All="TRUE" /><Display Level="None" AcceptEULA="FALSE" /><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/><Logging Level="Standard" Path="C:\WINDOWS\TEMP\ManagedSoftwareInstallers\Office365UninstallLog" /></Configuration>
"@
                    $XMLPath = Join-Path $ODTFolder "Uninstall.xml"
                    $UninstallXML | Set-Content -Path $XMLPath -Force | Out-Null
                    #$UninstallString = ($OfficeProgram.UninstallString + " DisplayLevel=False forceappshutdown=True").Replace("scenariosubtype=ARP","scenariosubtype=uninstall")        
                    $UninstallString = "$ODTPath /configure `"$XMLPath`""
                }
                elseif($OfficeProgram.UninstallString -like "*\Office Setup Controller\setup.exe*")
                {
                    Write-Host "Detected Office Setup Controller"
                    if($UseOffScrub)
                    {
                        Write-Host "Using OffScrub"
                        Write-Host "Downloading Remove-PreviousOfficeInstalls.ps1"
                        Get-GithubRepository -Owner OfficeDev -Repository 'Office-IT-Pro-Deployment-Scripts' -FilePath 'Office-ProPlus-Deployment/Remove-PreviousOfficeInstalls' -DestinationFolderPath 'C:\Windows\temp'
                        $ScriptPath = Join-Path 'C:\Windows\Temp' 'Office-ProPlus-Deployment\Remove-PreviousOfficeInstalls\Remove-PreviousOfficeInstalls.ps1'
                        # Dot-Sourcing the script into our session
                        . $ScriptPath
                        Remove-PreviousOfficeInstalls
                        $UninstallString = $null
                        $UseOffscript = $false
                    }
                    else
                    {
                        Write-Host "Generating Uninstall.xml"
                        $RetVal.InstallType = "Office Setup Controller"
                        $UninstallString = $OfficeProgram.UninstallString    
                        $splitpath = Split-Path $UninstallString.Split("/")[0].Replace("`"","") -Parent
                        $XMLPath = $splitpath + "\Uninstall.xml"
                        $Product = $UninstallString.Substring($UninstallString.IndexOf("/uninstall ")).Split(" ")[1]    
                    
                        $UninstallXML = @"
                <Configuration Product="$Product">
                    <Display Level="none" CompletionNotice="no" SuppressModal="yes" AcceptEula="yes" />
                    <Setting Id="SETUP_REBOOT" Value="NEVER" />
                </Configuration>
"@
                        Write-Host "Generating $XMLPath"
                        Write-Host $UninstallXML
                        $UninstallXML | Set-Content $XMLPath -Force | Out-Null
                        $UninstallString += " /config Uninstall.xml"
                    }
                }
                else
                {
                    $RetVal.InstallType = "Unknown"
                }
            
                if($UninstallString -ne $null)
                {
                    Write-Host "Uninstalling with uninstallstring - $UninstallString"
                    iex "cmd /c $UninstallString"
                    $Retval.UninstallString = $UninstallString
                    $RetVal.Result = "Ran modified uninstall string"
                }
                else
                {
                    # Write-Host "Silent Uninstallation method unknown for this edition of Office"
                    # $RetVal.Result = "Could not determine silent uninstall string"
                }
        
                new-object psobject -Property $RetVal
            }
        }
        $OfficeInstallations = Get-OfficeInstallations
        $OfficeInstallationCount = ($OfficeInstallations | measure).Count
        $Attempt++
    }
}
else
{
    Write-Host "Skipping undesired Office removal task."
}
##########################
if($null -eq $SharedComputerLicensing)
{
    $OSProductType = Get-WmiObject -ClassName Win32_OperatingSystem | select -ExpandProperty ProductType  # Check for Work Station (1)
    Write-Host "No value provided for SharedComputerLicensing"
    if($OSProductType -gt 1 -and $ProductID -like "*proplus*")
    {
        $SharedComputerLicensingInt = [int](Get-WindowsFeature RDS-RD-Server | select -ExpandProperty Installed)
    }
    else
    {
        $SharedComputerLicensingInt = [int]$false
    }
}
else
{
    Write-Host "SharedComputerLicensing specified: $SharedComputerLicensing"
    $SharedComputerLicensingInt = [int]$SharedComputerLicensing
}

if($LicenseValue -like "*-*-*-*-*" -or $SerialNumber -like "*-*-*-*-*")
{
    if($LicenseValue -like "*-*-*-*-*")
    {
        Write-Host "Using LicenseValue: $LicenseValue"
        $PIDKEY = "PIDKEY=`"$LicenseValue`""
    } 

    if($SerialNumber -like "*-*-*-*-*")
    {
        Write-Host "Using SerialNumber: $SerialNumber"
        $PIDKEY = "PIDKEY=`"$SerialNumber`""
    }
}




### Creating Shortcuts
Write-Host "Creating Desktop Shortcuts"
$InstallPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun" -Name InstallPath -ErrorAction SilentlyContinue  | select -ExpandProperty InstallPath

Function New-DesktopShortcut
{
    param($Name,$TargetPath)
    if(!(Test-Path $TargetPath))
    {
        Write-Warning "Unable to find $TargetPath"
        return
    }
    $DesktopShortcuts = Get-ChildItem "$($env:Public)\Desktop\*.lnk"
    $ResolvedDesiredPath = Resolve-Path $TargetPath
    $ShortcutFile = $DesktopShortcuts | ?{
        $ShortcutFile = $_
        $Shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($ShortcutFile)
        $ResolvedShortcutTarget = Resolve-Path $Shortcut.TargetPath
        return ($ResolvedShortcutTarget -eq $ResolvedDesiredPath)
    }
    if($ShortcutFile)
    {
        $ShortcutFileCount = $ShortcutFile | Measure | select -Expand Measure
        Write-Host "Found $ShortcutFileCount shortcuts pointing to $TargetPath"
        $ShortcutFile | ?{
            $Name -ne [io.path]::GetFileNameWithoutExtension($_)
        } | %{ 
            Write-Host "Removing Duplicate Shortcut $(Split-Path -Leaf $_) to $TargetPath"
            Remove-Item $_ 
        }
            
        $ShortcutFile = $ShortcutFile | ?{
            $Name -eq [io.path]::GetFileNameWithoutExtension($_)
        }
    }
        
    if(!$ShortcutFile)
    {
        $ShortcutFile = "$($env:Public)\Desktop\$Name.lnk"
    }
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
    $Shortcut.TargetPath = $TargetPath    
    $Shortcut.Save()
    # Write-Host "Shortcut created for $Name"
}

foreach($Program in $OfficePrograms)
{
    New-DesktopShortcut -Name $Program.Shortname -TargetPath (Join-Path -Path "$InstallPath\root\Office16" -ChildPath $Program.FileName)
}

Get-OfficeDeploymentToolkitLogs
return
Write-Host "Checking Logs"
$LogFiles = gci "$ConfigureLogFolderPath\*.log"
Write-Host "Found $($LogFiles.Count) Log files"
#$LogFiles | %{ Write-Host $_ }
$LogFilePath = $LogFiles | sort Name | select -Last 1
Write-Host "Selected: $(Split-Path $LogFilePath -Leaf)"
$Logs = Import-Csv $LogFilePath -Delimiter "`t"
$PrereqFailureSearchString = "Prereq::ShowPrereqFailure: "
Write-Host "Log: $LogFilePath"
$ErrorLogsOfInterest = $Logs | ?{$_.Message -like "$PrereqFailureSearchString*" -or $_.Message -like "*showui*"} | select -last 150
$LastErrorLogOfInterest = $ErrorLogsOfInterest | select -Last 1
if($LastErrorLogOfInterest)
{
    $IndexOfInterest = $Logs.IndexOf($LastErrorLogOfInterest)
    $StartIndex = [Math]::Max(0, ($IndexOfInterest - 5))
    $LogsOfInterest = $Logs[$StartIndex..$IndexOfInterest]
    $ErrorMessage = $LogsOfInterest | %{ $_.Message.Replace("  ","`r`n").Replace($PrereqFailureSearchString,"") }     
    Write-Host "ErrorMessage: $ErrorMessage"
}
else
{
    $LinesToShow = 150
    Write-Host "No interesting logs found. Dumping last $LinesToShow lines"
    $LogsToShow = ($Logs | select -Last $LinesToShow) -Join "`r`n"
    if($LogsToShow -like "*Cannot get the permission*" -or $LogsToShow -like "*User Cancelled the ProcessKiller*" -or $LogsToShow -like "*Starting Process Killer*")
    {
        throw "Cannot get the permission from user to kill the blocking apps. Aborting."
    }
}


