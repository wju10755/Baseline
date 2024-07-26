$TempFolder = "C:\temp"
$LogFile = "c:\temp\baseline.log"
$AcroFilePath = "c:\temp\Reader_en_install.exe"
# Clear console window
Clear-Host
 
# Set console formatting
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline;
    Write-Host -ForegroundColor $Color $Message;
}


# Print Script Title
#################################
$Padding = ("=" * [System.Console]::BufferWidth);
Write-Host -ForegroundColor "Red" $Padding -NoNewline;
Print-Middle "MITS - New Workstation Baseline Script";
Write-Host -ForegroundColor Cyan "                                                   version 11.0.2";
Write-Host -ForegroundColor "Red" -NoNewline $Padding; 
Write-Host "  "


############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Functions
# Function to write text with delay
function Write-Delayed {
    param(
        [string]$Text, 
        [switch]$NewLine = $true,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    $currentColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 25
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
    [Console]::ForegroundColor = $currentColor
}

# Create temp directory and baseline log
function Initialize-Environment {
    if (-not (Test-Path $TempFolder)) {
        New-Item -Path $TempFolder -ItemType Directory | Out-Null
    }
    if (-not (Test-Path $LogFile)) {
        New-Item -Path $LogFile -ItemType File | Out-Null
    }
}

# Set working directory
Set-Location
# Baseline Operations Log
function Write-Log {
    param (
        [string]$Message
    )
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Message"
}

$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }
Start-Sleep -Seconds 1
if ($Acrobat) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    Write-Host "Existing Acrobat Reader installation found. Skipping installation."
    [Console]::ResetColor()
} else {
    if (-not (Test-Path $AcroFilePath)) {
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Reader_en_install.exe"
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $URL -Method Head
        $fileSize = $response.Headers["Content-Length"]
        $ProgressPreference = 'Continue'
        Write-Host "Downloading Adobe Acrobat Reader ($fileSize bytes)..."
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        Write-Host " done."
        [Console]::ResetColor()
    }

    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1628608 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Start the installation process as a background job
        $installJob = Start-Job -ScriptBlock {
            Start-Process -FilePath $using:AcroFilePath -Args "/sAll /msi /norestart /quiet"
            Start-Sleep -Seconds 150
            # Create a FileSystemWatcher to monitor the specified file
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = "C:\Program Files (x86)\Common Files\adobe\Reader\Temp\*"
            $watcher.Filter = "installer.bin"
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName
            $watcher.EnableRaisingEvents = $true
            # When installer.bin is deleted, kill the acroread.exe process
            Register-ObjectEvent $watcher "Deleted" -Action {
                Start-Sleep -Seconds 15
                function Check-MsiexecSession {
                    $msiexecProcesses = Get-Process msiexec -ErrorAction SilentlyContinue
                    $hasSessionOne = $msiexecProcesses | Where-Object { $_.SessionId -eq 1 }
                    return $hasSessionOne
                }
                do {
                    Start-Sleep -Seconds 10
                    $msiexecSessionOne = Check-MsiexecSession
                } while ($msiexecSessionOne)
                [Console]::ForegroundColor = [System.ConsoleColor]::Green
                Write-Delayed "Installation complete." -NewLine:$true # Changed message and added new line
                [Console]::ResetColor()
                Write-Log "Adobe Acrobat installation complete." -ForegroundColor Green
            } | Out-Null
        }
    }
    # Outer loop to keep displaying the message while the installation job is running
    do {
        # Reset message display counter for each cycle
        $repetitions = 6
        for ($i = 1; $i -le $repetitions; $i++) {
            $dots = "." * $i
            # Clear the previous message
            Write-Host -NoNewline ("`r" + (' ' * ($message.Length + $repetitions)))
            # Display the current state of the message
            $message = "Installing Adobe Acrobat"
            Write-Host -NoNewline "`r$message$dots"
            Start-Sleep -Milliseconds 300
        }
    } while ((Get-Job -Id $installJob.Id).State -eq "Running")

    # Clear the line after installation is complete
    Write-Host -NoNewline ("`r" + (' ' * ($message.Length + $repetitions)))

    # Clean up the job
    Remove-Job -Id $installJob.Id

    Write-Host "Installation complete." -ForegroundColor Green
    Taskkill /f /im Reader_en_install.exe *> $null
    Start-Sleep -Seconds 30
    Taskkill /f /im msedge.exe *> $null
}