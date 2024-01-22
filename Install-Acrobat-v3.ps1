$ErrorActionPreference = "SilentlyContinue"

if (!(Test-Path -Path C:\temp)) {
    New-Item -ItemType directory -Path C:\temp *> $null
}

# Acrobat Installation
$AcroFilePath = "c:\temp\AcroRead.exe"
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
          Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" }
Start-Sleep -Seconds 1

if ($Acrobat) {
    Write-Host "Existing Acrobat Reader installation found." -ForegroundColor "Cyan"
} else {
    if (-not (Test-Path $AcroFilePath)) {
        # If not found, download it
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRead.exe"
        Write-Host "Downloading Adobe Acrobat Reader ( 277,900,248 bytes)..." -NoNewline
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        Write-Host " done." -ForegroundColor "Green"
    }

    # Validate successful download by checking the file size
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1452648 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Run c:\temp\AcroRdrDC2300620360_en_US.exe to install Adobe Acrobat silently
        Write-Host "Installing Adobe Acrobat Reader..." -NoNewline
        Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -PassThru | Out-Null
        Start-Sleep -Seconds 145
        Write-Host " done." -ForegroundColor "Green"
        Start-Sleep -Seconds 10
        # Create a FileSystemWatcher to monitor the specified file
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "C:\Program Files (x86)\Common Files\adobe\Reader\Temp\*"
        $watcher.Filter = "installer.bin"
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName
        $watcher.EnableRaisingEvents = $true

        # When installer.bin is deleted, kill the acroread.exe process
        Register-ObjectEvent $watcher "Deleted" -Action {
            Start-Sleep -Seconds 15
            #& taskkill /f /im acroread.exe
            #Write-Host "acroread.exe process killed" -ForegroundColor "Green"
        }

        function Check-MsiexecSession {
            $msiexecProcesses = Get-Process msiexec -ErrorAction SilentlyContinue
            $hasSessionOne = $msiexecProcesses | Where-Object { $_.SessionId -eq 1 }
        
            return $hasSessionOne
        }

        # Loop to continually check the msiexec process
        do {
        Start-Sleep -Seconds 10  # Wait for 10 seconds before checking again
        $msiexecSessionOne = Check-MsiexecSession
        } while ($msiexecSessionOne)
        # Once there are no msiexec processes with Session ID 1, kill acroread.exe
        Start-Sleep 15
        taskkill /f /im acroread.exe *> $null
        #Write-Host "Adobe Acrobat installation complete." -ForegroundColor Green

        } else {
        # Report download error
        Write-Host "Download failed. File size does not match." -ForegroundColor "Red"
        Start-Sleep -Seconds 5
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}
