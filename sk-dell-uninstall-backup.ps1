# Check if Dell Peripheral Manager is installed
Write-Host "Starting Dell bloatware removal`n" -NoNewline
$DPMpackageName = 'Dell Peripheral Manager'
$DPMpackage = Get-Package -Name $DPMpackageName -ErrorAction SilentlyContinue

if ($DPMpackage) {
    # Download Dell Peripheral Manager
    $ProgressPreference = 'SilentlyContinue'
    #Write-Host "Downloading Dell Peripheral Manager Script..."
    Invoke-WebRequest -Uri $DPMurl -OutFile $DPMzip *> $null

    # Extract the file
    Write-Host "Extracting Dell Peripheral Manager package..."
    Expand-Archive -Path $DPMzip -DestinationPath $DPMdir -Force

    # Run the script
    Write-Host "Removing Dell Peripheral Manager..."
    & "$DPMdir\Uninstall-DellPeripheralManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
    Write-Log "Removed Dell Peripheral Manager."
} else {
    Write-Host "Dell Peripheral Manager not found" -ForegroundColor "Red"
}

#Remove Dell Display Manager 
cd 
.\uninst.exe /S /v/qn
#$DDMurl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Uninstall-ddm.zip"
#$DDMzip = "C:\temp\Uninstall-ddm.zip"
#$DDMdir = "C:\temp\Uninstall-DDM"
#$DDMpackageName = 'Dell Display Manager'

#$DDMpackage = Get-Package -Name $DDMpackageName -ErrorAction SilentlyContinue

#if ($DDMpackage) {
#    # Download Dell Peripheral Manager
#    $ProgressPreference = 'SilentlyContinue'
#    Invoke-WebRequest -Uri $DDMurl -OutFile $DDMzip *> $null
#
#    # Extract the file
#    Write-Host "Extracting Dell Display Manager package..."
#    Expand-Archive -Path $DDMzip -DestinationPath $DDMdir -Force
#
#    # Run the script
#    Write-Host "Removing Dell Display Manager..." -NoNewline
#    & "$DDMdir\Uninstall-DellDisplayManager.ps1" -DeploymentType "Uninstall" -DeployMode "Silent" *> $null  
#    Write-Host " done." -ForegroundColor "Green"
#    Write-Log "Removed Dell Display Manager."
#} else {
#    Write-Host "Dell Display Manager not found" -ForegroundColor "Red"
#}

    
# Remove Dell Optimizer Core
#if (test-path -path "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe" ) {invoke-command -scriptblock {'C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe'} -ArgumentList "-remove -runfromtemp"}
$optimizerPath = "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}\DellOptimizer.exe"
if (Test-Path $optimizerPath) {
    Write-Host "Removing Dell Optimizer Core..." -NoNewline
    $command = "`"$optimizerPath`" -remove -runfromtemp -silent"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -NoNewWindow -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell Optimizer Core."
} else {
    Write-Host "Dell Optimizer Core installation not found." -foregroundColor "Red"
}
    
# Remove Dell Command Update (All Versions)
$Name = "Dell Command | Update*"
$ProcName = "DellCommandUpdate"
$Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
$LogFile = "C:\temp\Dell-CU-Uninst_$Timestamp.log"
$ProgramList = @( "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" )
$Programs = Get-ItemProperty $ProgramList -EA 0
$App = ($Programs | Where-Object { $_.DisplayName -like $Name -and $_.UninstallString -like "*msiexec*" }).PSChildName

if ($App) {
    Get-Process | Where-Object { $_.ProcessName -eq $ProcName } | Stop-Process -Force
    $Params = @(
        "/qn"
        "/norestart"
        "/X"
        "$App"
        "/L*V ""$LogFile"""
        )
        Write-Host "Removing Dell Command Update..." -NoNewline
        Start-Process "msiexec.exe" -ArgumentList $Params -Wait -NoNewWindow
        Write-Host " done." -ForegroundColor "Green"
        Write-Log "Removed Dell Command Update."
}
else {
    Write-Host "$Name installation not found." -foregroundColor "Red"
}


# Remove Dell Pair Application
$pairPath = "C:\Program Files\Dell\Dell Pair\Uninstall.exe"
if (Test-Path $pairPath) {
    Write-Host "Removing Dell Pair Application..." -NoNewline
    $pair = "`"$pairPath`" /S"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $pair" *> $null
    Start-Sleep -Seconds 10
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed Dell Pair Application."   
} else {
    #Write-Host "Dell Pair Uninstall.exe file does not exist."
    Write-Host "Dell Pair installation not found." -ForegroundColor "Red"
}

# Dell Support Assist Remediation Service
$filePath = "C:\ProgramData\Package Cache\{b2e99ca2-5292-470d-bf98-4d347c913748}\DellSupportAssistRemediationServiceInstaller.exe"
if (Test-Path $filePath) {
    Write=Host "Removing Dell Support Assist Remediation Service..." -NoNewline
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$filePath`" /uninstall /quiet" -NoNewWindow -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Dell Support Assist Remediation Service removed."
} else {
    Write-Host "Support Assist Remediation Service not found." -foregroundColor "Red"   
}

# Dell Support Assist OS Recovery Plugin for Dell Update
$DSARP = "C:\ProgramData\Package Cache\{9d6ba6ac-00ed-41bc-9a72-368346191765}\DellUpdateSupportAssistPlugin.exe"
if (Test-Path $DSARP) {
    Write-Host "Removing Dell Support Assist OS Recovery Plugin for Dell Update..." -NoNewline
    Start-Process -FilePath "$DSARP" -ArgumentList "/uninstall" -Wait *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Dell Support Assist OS Recovery Plugin for Dell Update removed."
    Start-Sleep -Seconds 15
    taskkill /f /im DellUpdateSupportAssistPlugin.exe *> $null

} else {
    Write-Host "Dell Support Assist OS Recovery Plugin for Dell Update not found" -ForegroundColor "Yellow"
}


# Remove Dell SupportAssist
#$exePath = "C:\ProgramData\Package Cache\{2600102a-dac2-4b2a-8257-df60c573fc29}\DellUpdateSupportAssistPlugin.exe"
#if (Test-Path $exePath) {
#    Write-Host "Removing Dell SupportAssist..." -NoNewline
#    $command = "`"$exePath`" /uninstall /quiet"
#    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" *> $null
#    Write-Host " done." -ForegroundColor "Green"
#    Write-Log "Removed Dell SupportAssist."
#    Start-Sleep -Seconds 3
#        } else {
#        #Write-Host "DellUpdateSupportAssistPlugin.exe does not exist."
#        Write-Host "Dell SupportAssist installation not found." -ForegroundColor "Red"
#    }

# Remove Support Assist v2
$ProgressPreference = 'SilentlyContinue'
$RevoURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/RevoCMD.zip"
$RevoFile = "c:\temp\RevoCMD.zip"
$RevoDestination = "c:\temp\RevoCMD"

# Download RevoCMD.zip
Invoke-WebRequest -Uri $RevoURL -OutFile $RevoFile -ErrorAction SilentlyContinue

# Check if RevoCMD.zip exists
if (Test-Path -Path $RevoFile) {
    # Extract RevoCMD.zip
    Expand-Archive -Path $RevoFile -DestinationPath $RevoDestination -Force
    
    # Run RevoUnPro with specified parameters
    Start-Process -FilePath "$RevoDestination\RevoUnPro.exe" -ArgumentList "/mu 'Dell SupportAssist' /path 'C:\Program Files\Dell\SupportAssistAgent' /mode Moderate /32"
}

# Trigger uninstall of remaining Dell applications
$Remaining = Get-Package | Where-Object {
    $_.Name -like 'dell*' -and
    $_.Name -notlike '*firmware*' -and
    $_.Name -notlike '*WLAN*' -and
    $_.Name -notlike '*HID*' -and
    $_.Name -notlike '*Touch*'
  }
    
  foreach ($package in $Remaining) {
    Write-Host "Triggering uninstall for $($package.Name)" -NoNewline
    Uninstall-Package -Name $package.Name -Force *> $null
    Write-Host " done." -ForegroundColor "Green"
    Write-Log "Removed $($package.Name)"
  }
  