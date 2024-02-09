$OfficePath = "c:\temp\OfficeSetup.exe"
$OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
Invoke-WebRequest -OutFile $OfficePath -Uri $OfficeURL -UseBasicParsing