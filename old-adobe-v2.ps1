# Acrobat Installation
$Acrobat = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" }
if ($Acrobat) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    $EAAIF = "Existing Acrobat Reader installation found."
    foreach ($Char in $EAAIF.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 30    
        }
    [Console]::ResetColor()
    [Console]::WriteLine()  
} else {
    #$AcroFilePath = "c:\temp\AcroRdrDC2300620360_en_US.exe"
    $AcroFilePath = "c:\temp\AcroRead.exe"
    if (-not (Test-Path $AcroFilePath)) {
        #$URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRdrDC2300620360_en_US.exe"
        $URL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/AcroRead.exe"
        #$DLAAR = "Downloading Adove Acrobat Reader (277,900,248 bytes...)"
        $DLAAR = "Downloading Adove Acrobat Reader..."
        foreach ($Char in $DLAAR.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        & $config.acrobatDownload
        Invoke-WebRequest -Uri $URL -OutFile $AcroFilePath -UseBasicParsing
        & $config.ClearPath
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()       
    }
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $AcroFilePath).Length
    $ExpectedSize = 1452648 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        $IAAR = "Installing Adobe Acrobat Reader..."
        foreach ($Char in $IAAR.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        & $config.acrobatNotification
        $process = Start-Process -FilePath $AcroFilePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -wait
        Start-Sleep -Seconds 5

    # Minimize the Acrobat installer window
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WindowHandler {
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    public static void MinimizeWindow(IntPtr hWnd) {
    ShowWindowAsync(hWnd, 2); // 2 corresponds to SW_MINIMIZE
        }
    }
"@

# Find the window handle and minimize
if ($process -and $process.MainWindowHandle -ne [IntPtr]::Zero) {
    [WindowHandler]::MinimizeWindow($process.MainWindowHandle)
}
        & $config.acrobatComplete
        Write-Log "Adobe Acrobat installed successfully."
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.`n")
        [Console]::ResetColor()
        [Console]::WriteLine()
        Start-Sleep -Seconds 2
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        # Report download error
        Write-Log "Download failed. File size does not match."
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        $AARDE = "Download failed or file size does not match."
        foreach ($Char in $AARDE.ToCharArray()) {
            [Console]::Write("$Char")
            Start-Sleep -Milliseconds 30    
            }
        [Console]::ResetColor()
        [Console]::WriteLine()    
        & $config.acrobatFailure
        Start-Sleep -Seconds 5
        Remove-Item -Path $AcroFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}
