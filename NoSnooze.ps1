function Start-JavaProcessSilently {
    param (
        [string]$JarPath,
        [string]$Arguments
    )

    # Create a new process start info object
    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

    # Set the filename to cmd.exe and arguments to run the Java command silently
    $processStartInfo.FileName = 'cmd.exe'
    $processStartInfo.Arguments = "/c java -jar `"$JarPath`" $Arguments"
    $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processStartInfo.CreateNoWindow = $true
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.RedirectStandardOutput = $true

    # Start the process
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
}

# Call the function with the path to the JAR file and any additional arguments
Start-JavaProcessSilently -JarPath "C:\temp\sikulixide-2.0.5.jar" -Arguments "-r C:\temp\NoSnooze.sikuli"
