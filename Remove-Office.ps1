$OfficeUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft 365 - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OfficeUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
        } 

taskkill /f /im procmon64.exe *> $null

Start-Sleep -Seconds 5

Start-Process -FilePath "C:\temp\procmon.exe" -ArgumentList "/AcceptEula" -WindowStyle Normal
# Move Procmon left
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinAPI {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
    }
"@

function Move-ProcessWindowToTopLeft([string]$processName) {
    $process = Get-Process | Where-Object { $_.ProcessName -eq $processName } | Select-Object -First 1
    if ($process -eq $null) {
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

Move-ProcessWindowToTopLeft -processName "procmon64" *> $null


$OneNoteUninstallStrings = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Microsoft OneNote - *"} | Select UninstallString).UninstallString
        ForEach ($UninstallString in $OneNoteUninstallStrings) {
            $UninstallEXE = ($UninstallString -split '"')[1]
            $UninstallArg = ($UninstallString -split '"')[2] + " DisplayLevel=False"
            Start-Process -FilePath $UninstallEXE -ArgumentList $UninstallArg -Wait
            
        }
taskkill /f /im procmon64.exe *> $null

