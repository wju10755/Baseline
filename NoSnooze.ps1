# Create a new process start info object
$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

# Set the filename to cmd.exe and arguments to run the Java command silently
$processStartInfo.FileName = 'cmd.exe'
$processStartInfo.Arguments = '/c java -jar "C:\temp\sikulixide-2.0.5.jar" -r "C:\temp\NoSnooze.sikuli"'
$processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$processStartInfo.CreateNoWindow = $true
$processStartInfo.UseShellExecute = $false
$processStartInfo.RedirectStandardOutput = $true

# Start the process
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processStartInfo
$process.Start() | Out-Null
$process.WaitForExit()
