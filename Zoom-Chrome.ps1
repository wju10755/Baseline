Add-Type -AssemblyName Microsoft.VisualBasic 
Add-Type -AssemblyName 'System.Windows.Forms'
$ID = (Start-Process chrome.exe -ArgumentList "https://uptime.mitsdev.com/status" -PassThru).id 
Sleep 2
[Microsoft.VisualBasic.Interaction]::AppActivate([Int32]$ID)
[System.Windows.Forms.SendKeys]::SendWait("^0^=^")




