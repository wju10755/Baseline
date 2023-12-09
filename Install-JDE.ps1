# Define the JDK version
$jdkVersion = "11.0.17"

# Function to check if JDK is installed
function Is-JdkInstalled {
    param (
        [string]$version
    )

    # Check the registry for JDK installation
    try {
        $jdkPath = Get-ChildItem -Path "HKLM:\SOFTWARE\JavaSoft\Java Development Kit" -ErrorAction Stop | Get-ItemProperty | Where-Object { $_.JavaHome -like "*jdk$version*" }
        return $jdkPath -ne $null
    } catch {
        return $false
    }
}

# Check if JDK 11.0.17 is already installed
if (Is-JdkInstalled -version $jdkVersion) {
    Write-Host "JDK $jdkVersion is already installed."
} else {
    # Define the path to the JDK installer
    $installerPath = "C:\temp\jdk-11.0.17_windows-x64_bin.exe"

    # Define the silent installation arguments
    $arguments = "/s"

    # Create a new process start info object
    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

    # Set the filename to the installer and add the silent installation arguments
    $processStartInfo.FileName = $installerPath
    $processStartInfo.Arguments = $arguments
    $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processStartInfo.CreateNoWindow = $true
    $processStartInfo.UseShellExecute = $false

    # Start the installation process
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    $process.WaitForExit()

    # Check the exit code
    if ($process.ExitCode -eq 0) {
        Write-Host "JDK installed successfully."
    } else {
        Write-Host "JDK installation failed with exit code: $($process.ExitCode)"
    }
}
