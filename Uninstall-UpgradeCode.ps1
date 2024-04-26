Write-Host "UpgradeCode: $UpgradeCode"
$ProductCode = Get-ProductCode -UpgradeCode $UpgradeCode
Write-Host "ProductCode: $ProductCode"

if (!$ProductCode) {
    throw "Unable to find ProductCode for UpgradeCode: $UpgradeCode"
}

$InstallerLogFile = New-ImmyTempFile

$Arguments = @"
/c msiexec /X {$ProductCode} /qn /l*v "$InstallerLogFile" /noreboot REBOOT=REALLYSUPPRESS
"@

Write-Host "Arguments: $Arguments"
$Process = Start-ProcessWithLogTail cmd -ArgumentList $Arguments -LogFile $InstallerLogFile -RegexFilter "error"
Get-MSIErrorDetails $Process.ExitCode
Write-Host "ExitCode: $($Process.ExitCode)"