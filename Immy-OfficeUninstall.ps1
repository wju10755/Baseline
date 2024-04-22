if(!$SoftwareName) {
    $SoftwareName = "Microsoft 365 Home Premium"
}

$ProductReleaseId = Get-Office365ProductIDFromDisplayName $SoftwareName

Invoke-ImmyCommand -Timeout 1800 {
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


#region Functions
Function Get-Office365ChannelName
{
    param([string]$FriendlyChannelName)
    $DesiredChannel = switch($FriendlyChannelName)
    {
        "Current Channel" {"Current"}
        "Current Channel (Preview)" {"CurrentPreview"}
        "Monthly Enterprise Channel" {"MonthlyEnterprise"}
        "Semi-Annual Enterprise Channel" {"SemiAnnual"}
        "Semi-Annual Enterprise Channel (Preview)" {"SemiAnnualPreview"}
    }
    return $DesiredChannel
}

Function Get-Office365Channel
{
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    if(!(Test-Path $RegPath))
    {
        Write-Warning "Path doesn't exist: $RegPath"
        Write-Warning "Unable to retrieve UpdateChannel"
        return
    }
    $CurrentCDNBaseUrl = Get-ItemProperty -Path $RegPath -Name CDNbaseUrl | %{$_.CDNBaseUrl}
    if(!$CurrentCDNBaseUrl)
    {
        Write-Warning "CDNBaseUrl not found in $RegPath"
        Write-Warning "Unable to retrieve UpdateChannel"
        return
    }
    switch($CurrentCDNBaseUrl)
    {
        "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60" { "Current Channel" }

        "http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be" { "Current Channel (Preview)" }

        "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6" { "Monthly Enterprise Channel" }

        "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" { "Semi-Annual Enterprise Channel" }

        "http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf" { "Semi-Annual Enterprise Channel (Preview)" }

        "http://officecdn.microsoft.com/pr/5440fd1f-7ecb-4221-8110-145efaa6372f" { "Beta Channel" }
        default { Write-Warning "Unable to find Channel Name for $CurrentCDNBaseUrl"}
    }
}
Function Get-OfficeDeploymentToolkitLogs
{
    if(!$LoggingPath -or !(Test-Path $LoggingPath))
    {
        $LoggingPath = $env:temp
        Write-Host "Logging path not provided, defaulting to: $LoggingPath"
    }
    Write-Host "Checking Logs"
    $LogFiles = dir "$LoggingPath\$($env:ComputerName)*.log"
    # Write-Host "Found $($LogFiles.Count) Log files"
    # $LogFiles | %{ Write-Host $_ }
    $LogFilePath = $LogFiles | sort Name | select -Last 1
    # Write-Host "Selected: $(Split-Path $LogFilePath -Leaf)"
    $Logs = Import-Csv $LogFilePath -Delimiter "`t"
    $PrereqFailureSearchString = "Prereq::ShowPrereqFailure: "
    Write-Host "Log: $LogFilePath"
    Function Split-JsonLog
    {
        param([string]$JsonLogString)
        $Pattern = '(.*?)(({|\[).*(}|\]))'
        if($JsonLogString -match $Pattern)
        {
            $Text = $Matches[1]
            $JsonString = $matches[2]
            if($JsonString)
            {
                try
                {
                    $JsonObject = ConvertFrom-Json $JsonString -ErrorAction SilentlyContinue
                }
                catch
                {
                    $Text += " " + $JsonObject
                }
            }
            return [psobject]@{"Text"=$Text.Trim();"Json"=$JsonObject}
        }
    }
    Function Expand-MessageData
    {
        param($Log)
        $SplitLog = Split-JsonLog $Log.Message
        $MethodName = $SplitLog.Text
        $InnerMessage = $SplitLog.Json        
        $Log | Add-Member -NotePropertyName "Method" -NotePropertyValue $MethodName       
        if($InnerMessage -and $InnerMessage -isnot [string])
        {
            $InnerMessage | Get-Member  -MemberType NoteProperty -ErrorAction SilentlyContinue | %{ 
                $Member = $_
                $Log | Add-Member -NotePropertyName "$MethodName`_$($Member.Name)" -NotePropertyValue $InnerMessage."$($Member.Name)"
            }
        }
        # if($InnerMessage.ContextData)
        # {
        #     $ContextData = Split-JsonLog $InnerMessage.ContextData            
        #     $Log | Add-Member -NotePropertyName "ContextDataMessage" -NotePropertyValue $ContextData.Text
        #     $Log | Add-Member -NotePropertyName "ContextData" -NotePropertyValue $ContextData.Json
        # }
        $Log | Add-Member -NotePropertyName "InnerError" -NotePropertyValue $InnerMessage.Error
        return $Log
    }
    $ExpandedLogs = $Logs | %{ Expand-MessageData  $_ } #| select -Last 20
    # $Logs | select -first 5 -skip 29 | %{ Expand-MessageData  $_ }
    # return
    # $Logs | ?{$_.Level -eq "Error"}
    # return
    $ErrorLogsOfInterest = $ExpandedLogs | ?{$_.Level -eq "Unexpected" -or $_.Message -like "$PrereqFailureSearchString*" -or $_.Message -like "*showui*"} | select -last 150
    $LastErrorLogOfInterest = $ErrorLogsOfInterest | select -Last 1
    if($LastErrorLogOfInterest)
    {
        $IndexOfInterest = $Logs.IndexOf($LastErrorLogOfInterest)
        $StartIndex = [Math]::Max(0, ($IndexOfInterest - 5))
        $LogsOfInterest = $Logs[$StartIndex..$IndexOfInterest]
        $ErrorMessage = $LogsOfInterest | %{ $_.Message.Replace("  ","`r`n").Replace($PrereqFailureSearchString,"") } 
        $ErrorMessage | %{ 
            if($_ -match 'PerformMSITransitions::HandleStateAction (\{.*\})')
            {
                $matches[1] | ConvertFrom-Json | select ErrorCode, ErrorType, ErrorMessage, ErrorDetails, ContextData        
            }
            else
            {
                $_
            }
        }    
    }
}
Function Format-XML ([xml]$xml, $indent=2)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = $Indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    Write-Output $StringWriter.ToString()
}
function Get-GithubRepository
{
    Param
    (
        # Please provide the repository owner
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Owner,
        # Please provide the name of the repository
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Repository,
        # Please provide a branch to download from
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Branch = 'master',
        # Please provide a list of files/paths to download
        [Parameter(Mandatory=$true,Position=3)]
        [string[]]$FilePath,
        # Please provide a list of files/paths to download
        [Parameter(Mandatory=$true,Position=3)]
        [string]$DestinationFolderPath
    )
    Write-Verbose "Ensuring $DestinationFolderPath Exists"
    New-Item -Type Container -Force -Path $DestinationFolderPath | Out-Null
    Write-Verbose "Downloading..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::UTF8
    $baseUri = "https://api.github.com/"
    $args = "repos/$Owner/$Repository/contents/$FilePath"
    $objects = Invoke-RestMethod -Uri $($baseuri+$args)
    $files = $objects | where {$_.type -eq "file"}
    $directories = $objects | where {$_.type -eq "dir"}
    $directories | ForEach-Object { Get-GithubRepository -Owner $Owner -Repository $Repository -FilePath $_.path -DestinationPath $($DestinationPath+$_.name) }
    foreach ($item in $files.Path)
    {
        Write-Verbose -Message "$item in FilePath"
        if ($item -like '*.*')
        {
            Write-Debug -Message "Attempting to create $DestinationFolderPath\$item"
            New-Item -ItemType File -Force -Path "$DestinationFolderPath\$($item)" | Out-Null
            $url = "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/$($item)"
            Write-Debug -Message "Attempting to download from $url"
            ($wc.DownloadString("$url")) | Out-File "$DestinationFolderPath\$item"
        }
        else
        {
            Write-Debug -Message "Attempting to create $DestinationFolderPath\$item"
            New-Item -ItemType Container -Force -Path "$DestinationFolderPath\$item" | Out-Null
            $url = "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/$item"
            Write-Debug -Message "Attempting to download from $url"
        }
    }    
}
#endregion Functions

#Set parameters for testing
if($null -eq $SoftwareName)
{
    $SoftwareName = "Microsoft 365 Apps for business"
    $DisplayVersion = "16.0.12325.20344"
}
###
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


Write-Host "Installing $ProductID $Version"
$ConfiguredChannel = Get-Office365Channel | %{ Get-Office365ChannelName $_ }

if($ProductID -like "*2019Volume")
{
    $Channel = "PerpetualVL2019"
}

elseif($ProductID -like "*2021Volume")
{

    $Channel = "PerpetualVL2021"

}
else
{
    if($UpdateChannel)
    {
        $DesiredChannel = Get-Office365ChannelName -FriendlyChannelName $UpdateChannel
        Write-Host "Configured Update Channel: $ConfiguredChannel"
        Write-Host "Desired Update Channel: $DesiredChannel"
        if($DesiredChannel -ne $ConfiguredChannel)
        {
            Write-Warning "Configured Update Channel $ConfiguredChannel doesn't match DesiredChannel $DesiredChannel"
            $TestResult = $false
        }
        $Channel = $DesiredChannel
    }
}



Write-Host "Current selected channel is $Channel"
$ForceAppClosureString = "FALSE"
if($ForceAppClosure -eq $true)
{
    $ForceAppClosureString = "TRUE"
}
############################
$ODTFolder = Join-Path $env:systemroot "Temp\ImmyBot\OfficeDeploymentToolkit"
New-Item -ItemType Directory -Path $ODTFolder -ErrorAction SilentlyContinue -Force | Out-Null

$TargetPath = $ODTFolder
$DownloadLogFolderPath = Join-Path $ODTFolder "DownloadLog"
New-Item -ItemType Directory -Path $DownloadLogFolderPath -ErrorAction SilentlyContinue -Force | Out-Null

$ConfigureLogFolderPath = Join-Path $ODTFolder "ConfigureLog"
New-Item -ItemType Directory -Path $ConfigureLogFolderPath -ErrorAction SilentlyContinue -Force | Out-Null
if((Get-Process setup -ErrorAction SilentlyContinue))
{
    Write-Host "Killing setup.exe"
    taskkill /im setup.exe /f 2>&1 | Out-Null
}
$ODTUrl = "https://immybot.blob.core.windows.net/software/MicrosoftOffice365/setup.exe"
$ODTPath = Join-Path $ODTFolder "setup.exe"
try {
    (New-Object System.Net.WebClient).DownloadFile($ODTUrl, $ODTPath)
}
catch
{
    $_ | fl *
    Start-BitsTransfer $ODTUrl $ODTPath
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



if($SpecificVersion)
{
    $ChannelVersionXML = "Version=`"$Version`""
}
elseif($Channel)
{
    $ChannelVersionXML = "Channel=`"$Channel`""
}
else
{
    # Values prior to 2021-01-05 changes to support Channel
    $ChannelVersionXML = "Channel=`"Monthly`" Version=`"16.0.12325.20344`""
    # 2021-02-04 - Darren Kattan - Removing hardcoded version to prevent ODT from failing to install out of support version of Project in the future
    $ChannelVersionXML = "Channel=`"Monthly`""
}
if(!$LanguageID)
{
    $LanguageID = 'MatchOS'
}
# 10/11/2022 - Nicholas Lowrey-Dufour - Added the capability to specify multiple langIDs
$LanguageIDs = $LanguageID -Split ";" | Where-Object {$_ -ne ""}
$LanguageIDsXML = ($LanguageIDs | Foreach-Object {"<Language ID=`"$_`" />"}) -Join "`n"

if($IncludeProofingTools -eq $true)
{
    $ProofingToolsXML = "<Product ID=`"ProofingTools`">$LanguageIDsXML</Product>"
}
$DownloadConfig = @"
<Configuration>
  <Add SourcePath="$TargetPath" $MigrateArchXML $ChannelVersionXML>
    <Product ID="$ProductID">
      $LanguageIDsXML      
    </Product>
    $ProofingToolsXML
  </Add>
<Display Level="None" AcceptEULA="TRUE" />
<Logging Path="$DownloadLogFolderPath" />
</Configuration>
"@;
# <RemoveMSI All="False" />
#Version="$Version" SourcePath="$TargetPath"
$InstallConfig = @"
<Configuration>
  <Add $MigrateArchXML $ChannelVersionXML>
    <Product ID="$ProductID" $PIDKEY>
      $LanguageIDsXML
      <ExcludeApp ID="Groove" />
"@
    if($ExcludeTeams)
    {
        $InstallConfig += '<ExcludeApp ID="Teams" />'
    }
    if($ExcludeSkypeForBusiness)
    {
        $InstallConfig += '<ExcludeApp ID="Lync" />'
        $ProductIDsToRemove += 'Lync'
    }
    if($ExcludeAccess)
    {
        $InstallConfig += '<ExcludeApp ID="Access" />'
    }
    if($ExcludeInfoPath)
    {
        $InstallConfig += '<ExcludeApp ID="InfoPath" />'
    }
    if($ExcludeOneNote)
    {
        $InstallConfig += '<ExcludeApp ID="OneNote" />'
    }
    if($ExcludeOutlook)
    {
        $InstallConfig += '<ExcludeApp ID="Outlook" />'
    }
    if($ExcludePublisher)
    {
        $InstallConfig += '<ExcludeApp ID="Publisher" />'
    }
    $InstallConfig += @"      
    </Product>        
    $ProofingToolsXML
  </Add>
"@

if($ProductIDsToRemove)
{
    $InstallConfig += '<Remove All="FALSE">'
    foreach($ProductIDToRemove in $ProductIDsToRemove)
    {
        $InstallConfig += "<Product ID=`"$ProductIDToRemove`"></Product>"
    }    
    $InstallConfig += '</Remove>'
}

$UpdatesEnabled = "TRUE"
if($DisableUpdates -eq $true)
{
    $UpdatesEnabled = "FALSE"
}
$InstallConfig += @"
<Updates Enabled="$UpdatesEnabled" />
<RemoveMSI />
<Display Level="NONE" AcceptEULA="TRUE" />
<Logging Path="$ConfigureLogFolderPath" />
<Property Name="AUTOACTIVATE" Value="TRUE"/>
<Property Name="FORCEAPPSHUTDOWN" Value="$ForceAppClosureString"/>
<Property Name="SharedComputerLicensing" Value="$SharedComputerLicensingInt"/>
<Property Name="PinIconsToTaskbar" Value="TRUE"/>
"@

# if($TenantName)
# {
#     $InstallConfig += @"
# <AppSettings>
#     <Setup Name="Company" Value="$TenantName">
# </AppSettings>
# "@
# }

$InstallConfig += @"

</Configuration>
"@;
$uninstallconfig = @"
<Configuration>
  <Remove All="FALSE">
  <Product ID="$ProductID" >
      $LanguageIDsXML      
    </Product>
  </Remove>
  <Property Name="SharedComputerLicensing" Value="0" />
  <Property Name="SCLCacheOverride" Value="0" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/>
  <Display Level="None" AcceptEULA="TRUE" />
  <Logging Level="Standard" Path="$ConfigureLogFolderPath"/>
</Configuration>
"@
#   <RemoveMSI All="TRUE" />

### Copy xml-s to local   

[xml]$DownloadConfigxml = $DownloadConfig   
New-Item -ItemType File -Path "$TargetPath\DownloadConfig$ProductID.xml" -Value $DownloadConfigxml.InnerXml -Force -ErrorAction SilentlyContinue | Out-Null
$InstallConfigFormatted = Format-XML $InstallConfig 
Write-Host $InstallConfigFormatted
New-Item -ItemType File -Path "$TargetPath\InstallConfig$ProductID.xml" -Value $InstallConfigFormatted -Force -ErrorAction SilentlyContinue | Out-Null
    
[xml]$uninstallconfigxml = $uninstallconfig
New-Item -ItemType File -Path "$TargetPath\UninstallConfig$ProductID.xml" -Value $uninstallconfigxml.InnerXml -Force -ErrorAction SilentlyContinue | Out-Null

### Create corresponding batch files on the local
    
New-Item -ItemType File -Path "$TargetPath\Download.bat" -Value "start /b %~dp0setup.exe /download %~dp0DownloadConfig$ProductID.xml" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType File -Path "$TargetPath\Install.bat" -Value "start /b %~dp0setup.exe /configure %~dp0InstallConfig$ProductID.xml" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType File -Path "$TargetPath\Uninstall.bat" -Value "start /b %~dp0setup.exe /configure %~dp0UninstallConfig$ProductID.xml" -Force -ErrorAction SilentlyContinue | Out-Null
$OfficeConfigRegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
# Fix issue where manual Office updates and repairs throw an error indicating the computer is "Offline"
# A long time ago I used to overwrite the UpdateUrl and Update Channel values in the config file above to a path in the temp folder
# This folder gets delete eventually, making the URL invalid, causing Office to think the computer is "Offline"

$UpdateChannel = Get-ItemProperty -Path $OfficeConfigRegPath -Name UpdateChannel -ErrorAction SilentlyContinue | select -expand UpdateChannel
$UpdateURL = Get-ItemProperty -Path $OfficeConfigRegPath -Name UpdateUrl -ErrorAction SilentlyContinue | select -expand UpdateUrl
if($UpdateChannel -like "C:\Windows\temp\ManagedSoftwareInstallers\*-Current")
{
    Remove-ItemProperty -Path $OfficeConfigRegPath -Name UpdateChannel -Force -ErrorAction SilentlyContinue
}

if($UpdateURL -like "C:\Windows\temp\ManagedSoftwareInstallers\*-Current")
{
    Remove-ItemProperty -Path $OfficeConfigRegPath -Name UpdateUrl -Force -ErrorAction SilentlyContinue
}

### Force Office downloading

# run batch file to Download
# $DownloadConfig
# # return "Hello";
# try
# {
#     Write-Host "Starting download of $ProductID $Version $ArcVersion-Bit"
#     $DownloadProcess = Start-Process "cmd.exe" "/c $TargetPath\Download.bat" -Wait -PassThru -ErrorAction 0
#     Write-Host "$($DownloadProcess.ExitCode)"
# }
# catch
# {
#     Write-Host "$_"
# }

if($ArcVersion)
{
    Write-Host "Starting Install of $ProductID $Version $ArcVersion-Bit"
}
else
{
    Write-Host "Starting Install of $ProductID $Version Platform Not Specified"
}
$Process = Start-Process "cmd.exe" -ArgumentList "/c $TargetPath\Install.bat" -PassThru -Wait
# $Timeout = 1700
# do{
#     sleep -s 1
#     $Timeout--
# } until ($Timeout -le 0 -or ($Process.HasExited -eq $true))
# if($Process.HasExited -ne $true)
# {
#     Write-Host "Setup process did not exit before timeout elapsed. Force Quitting..." -NoNewLine
#     taskkill /PID $Process.Id /F 2>&1 | Out-Null
#     Write-Host "Done."
# }

Write-Host "Process Exit Code: $($Process.ExitCode)"

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


