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

# Call the function Show-Spinner with the command and a label
Show-Spinner -Script {& 'C:\temp\Remove-Office.ps1'} -Message "Removing Pre-Installed Microsoft 365 Applications..."
Start-Sleep -Seconds 3
