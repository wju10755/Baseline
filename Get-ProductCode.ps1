[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName = 'UpgradeCode')]
    [Guid]$UpgradeCode,
    [Parameter(Mandatory, ParameterSetName = 'DisplayName')]
    [string]$DisplayName,
    [switch]$IncludeUserContext
)

if($UpgradeCode)
{
    $UpgradeCodeHexString = Convert-GUIDtoMsiHexString $UpgradeCode

    if ($IncludeUserContext) {
        $ProductCodeHexString = Invoke-HKCU {
            $UpgradeCodeHexString = $using:UpgradeCodeHexString
            $RegistryKey = Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeHexString","HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeHexString" -ErrorAction SilentlyContinue
            $RegistryKey.Property | Select-Object -first 1
        }
    }

    $ProductCodeHexString = Invoke-ImmyCommand {
        $UpgradeCodeHexString = $using:UpgradeCodeHexString
        $RegistryKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeHexString","HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeHexString" -ErrorAction SilentlyContinue
        $RegistryKey.Property | Select-Object -first 1
    }

    if ($ProductCodeHexString) {
        Convert-MsiHexStringToGuid $ProductCodeHexString
    } else {
        Write-Error "Unable to find ProductCode for UpgradeCode $UpgradeCode"
    }
} else
{
    Invoke-ImmyCommand {
        $DisplayName = $using:DisplayName
        Function IsGuid
        {
            param([string]$PossibleGuid)
            try
            {
                $null = [Guid]::New($PossibleGuid)
                return $true
            } catch
            {
                return $false
            }
        }
        $RegistryKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name DisplayName -ErrorAction SilentlyContinue
        $ProductCode = $RegistryKey | Where-Object {$_.DisplayName -like $DisplayName -and (IsGuid $_.PSChildName) } | Select-Object -Expand PSChildName
        $ProductCode
    }
}
