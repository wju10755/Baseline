$SWName = Get-InstalledSoftware "Dell", "Microsoft Update Health Tools", "ExpressConnect Drivers & Services" | ? DisplayName -NotLike "Dell Command | Update for Windows*" | select -ExpandProperty DisplayName

if ($SWName) {
    try {
        $SWName | % {
            $param = @{
                Name        = $_
                ErrorAction = "Stop"
            }

            if ($_ -eq "Dell Optimizer Service") {
                # uninstallation isn't unattended without -silent switch
                $param.addArgument = "-silent"
            }

            Uninstall-ApplicationViaUninstallString @param
        }
    } catch {
        Write-Error "There was an error when uninstalling bloatware: $_"
    }
} else {
    "There is no bloatware detected"
}
