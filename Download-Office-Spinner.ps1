# Define a function to character
function Show-Spinner {
    param(
        [scriptblock]$Script, # The script to run in the background
        [string]$Message = "Please wait..." # The message to display
    )

    # Import the required module for Start-Job cmdlet
    Import-Module -Name Microsoft.PowerShell.Management

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

    # Backspace the '|' character and write "done."
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    Write-Host -NoNewline "done." -ForegroundColor Green

    # Move the cursor to the next line
    #Write-Host ""
    
    # Remove the job
    Remove-Job -Name $job.Name
}

# Call the function Show-Spinner with the command and a label
Show-Spinner -Script {& 'C:\temp\Download-Office.ps1'} -Message "Downloading Microsoft Office 365..."
Start-Sleep -Seconds 3
