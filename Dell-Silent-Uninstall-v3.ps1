Set-Executionpolicy RemoteSigned -Force *> $null

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


$moduleName = "CommonStuff" # replace with your module name

# Check if the module is already installed
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        #Write-Host "Module '$moduleName' installed successfully."
    } catch {
        Write-Error "Failed to install module '$moduleName': $_"
        exit
    }
} else {
    #Write-Host "Module '$moduleName' is already installed."
}

# Import the module
try {
    Import-Module -Name $moduleName -ErrorAction Stop
    #Write-Host "Module '$moduleName' imported successfully."
} catch {
    Write-Error "Failed to import module '$moduleName': $_"
}


# Start Procmon
Start-Procmon