function Remove-PreInstalledOffice {
    # Define the path to temp folder
    $tmp = "c:\temp"

    # Define the path to the VBScript
    $scriptPath = "C:\temp\OffScrubc2r.vbs"

    # Define output file path
    $outFile = "c:\temp\OffScrubc2r.vbs"

    if (-not (Test-Path $tmp)) {
        Write-Host "Creating temp directory."
        mkdir c:\temp
    }

    # Check if the file already exists
    if (!(Test-Path -Path $outFile)) {
        # Download the file
        Invoke-WebRequest -OutFile $outFile https://advancestuff.hostedrmm.com/labtech/transfer/installers/OffScrubc2r.vbs
    }

    # Define the spinner
    $spinner = @('|', '/', '-', '\')

    # Output the initial message
    Write-Host "Removing Pre-Installed Office... " -NoNewline

    # Start the VBScript in a new process
    $process = Start-Process -FilePath "cscript.exe" -ArgumentList "/B //Nologo $scriptPath" -PassThru -NoNewWindow

    # Display the spinner until the process completes
    while (!$process.HasExited) {
        foreach ($spin in $spinner) {
            Write-Host "`b$spin" -NoNewline
            Start-Sleep -Milliseconds 100
        }
    }

    # Output a newline to clean up the spinner
    Write-Host "`n"
    Write-Host " "
    Write-Host "Uninstall Complete"
}

# Call function
Remove-PreInstalledOffice