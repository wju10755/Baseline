# Define a function to display a spinning character
function Show-Spinner {
    param(
        [scriptblock]$Script, # The script to run in the background
        [string]$Message = "Please wait..." # The message to display
    )
    # Define an array of characters to spin
    $chars = @('/', '-', '\', '|')
    # Initialize a counter
    $i = 0
    # Start the script as a job
    $job = Start-Job -ScriptBlock $Script
    # Write the message and the first character
    Write-Host -NoNewline "$Message $($chars[$i])"
    # Loop until the job is done
    while ($job.State -eq "Running") {
        # Increment the counter and wrap around if needed
        $i = ($i + 1) % $chars.Length
        # Move the cursor back and overwrite the character
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        Write-Host -NoNewline $chars[$i]
        # Sleep for a short time
        Start-Sleep -Milliseconds 100
    }
    # Move the cursor to the next line
    Write-Host
    # Remove the job
    Remove-Job -Name $job.Name
}

# Call the function Show-Spinner with the modified command and a label
$scriptBlock = {
    & 'C:\temp\Win11Debloat\Win11Debloat.ps1' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent
}
Show-Spinner -Script $scriptBlock -Message "Removing Windows 11 Bloatware..."
Start-Sleep -Seconds 3
