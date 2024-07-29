# Check if the script is running as an administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!"
    Start-Sleep -Seconds 8
    return
}

Start-Transcript -Path "c:\temp\mits-rename.log"

function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline;
    Write-Host -ForegroundColor $Color $Message;
}


# Print Script Title
#################################
$Padding = ("=" * [System.Console]::BufferWidth);
Write-Host -ForegroundColor "Red" $Padding -NoNewline;
Print-Middle "MITS - New Workstation Baseline Script";
Write-Host -ForegroundColor Cyan "                                                 =Workstation Rename Module=";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "
Start-Sleep -Seconds 2


# Prompt the user to rename the computer
$computerName = Read-Host "Enter the new computer name"

# Rename the computer
Rename-Computer -NewName $computerName -Force -Restart

# Wait for the computer to restart
Start-Sleep -Seconds 60 

# Log back in as the previous user
$previousUser = "mitsadmin"
$password = "@dvance10755" | ConvertTo-SecureString -AsPlainText -Force

# Convert the secure string password to plain text
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

Start-Sleep -Seconds 25

# Create a scheduled task to run the command after login
$taskName = "ContinueWorkstationBaseline"
$command = "irm bit.ly/mits-baseline | iex"

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"$command`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $previousUser
$principal = New-ScheduledTaskPrincipal -UserId $previousUser -LogonType Password -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Log in as the previous user
Start-Process "cmd.exe" -ArgumentList "/c runas /user:$previousUser powershell.exe" -Wait

# Clean up the scheduled task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false