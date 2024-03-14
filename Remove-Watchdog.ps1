# Get the Dell Watchdog Timer application
$app = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name = 'Dell Watchdog Timer'"

# Check if the application was found
if ($app -ne $null) {
    # Uninstall the application
    $app.Uninstall()

    Write-Host "Dell Watchdog Timer has been uninstalled."
} else {
    Write-Host "Dell Watchdog Timer is not installed."
}

