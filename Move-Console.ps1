function Move-ProcessWindowToBottomRight([string]$processName) {
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

    # Get the screen size
    $screenWidth = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
    $screenHeight = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height

    # Calculate the new position
    $x = $screenWidth - $windowWidth
    $y = $screenHeight - $windowHeight

    [WinAPI]::MoveWindow($hWnd, $x, $y, $windowWidth, $windowHeight, $true)
}

Move-ProcessWindowToBottomRight -processName "powershell" *> $null