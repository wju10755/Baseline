Set-Executionpolicy RemoteSigned -Force *> $null
Start-Transcript -path "c:\temp\Office_Uninstall.log"

# Define the function to move the process window to top left
function Move-ProcessWindowToTopLeft([string]$processName) {
    $process = Get-Process | Where-Object { $_.ProcessName -eq $processName } | Select-Object -First 1
    if ($null -eq $process) {
        Write-Host "Process not found."
        return
    }

    $hWnd = $process.MainWindowHandle
    if ($hWnd -eq [IntPtr]::Zero) {
        Write-Host "Window handle not found."
        return
    }

    $windowRect = New-Object WinAPI+RECT
    [WinAPI]::GetWindowRect($hWnd, [ref]$windowRect)
    $windowWidth = $windowRect.Right - $windowRect.Left
    $windowHeight = $windowRect.Bottom - $windowRect.Top

    # Set coordinates to the top left corner of the screen
    $x = 0
    $y = 0

    [WinAPI]::MoveWindow($hWnd, $x, $y, $windowWidth, $windowHeight, $true)
}

# Define the function to start Procmon
function Start-Procmon {
    $ps = Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
    $wshell = New-Object -ComObject wscript.shell
    Start-Sleep -Seconds 3
    $wshell.SendKeys("^a")
    Start-Sleep -Seconds 2

    Move-ProcessWindowToTopLeft -processName "procmon64" *> $null
}

# Define the function to stop Procmon
function Stop-Procmon {
    $wshell = New-Object -ComObject wscript.shell
    $wshell.SendKeys("^a")
    Start-Sleep -Seconds 2
    taskkill /f /im procmon* *> $null
}

    # Start Procmon
    Start-Procmon

    # Trigger uninstall of all pre-installed versions of Microsoft OneNote Apps
    $OneNoteUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft OneNote - *"} | Select UninstallString).UninstallString
    ForEach ($UninstallString in $OneNoteUninstallStrings) {
        $UninstallEXE = ($UninstallString -split '"')[1]
        $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
        Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
    }

    # Stop Procmon
    Stop-Procmon

    Stop-Transcript
