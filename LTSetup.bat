@echo off
setlocal

set tmp=C:\temp
set LTPKG=C:\temp\Warehouse_Agent_MSI_Install.zip
set LTURL=https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse_Agent_MSI_Install.zip
set LTBAT=C:\temp\install.bat

echo Starting LTAgent Setup....

for /L %%i in (30,-1,0) do (
	<nul set /p =%%i seconds remaining...
	timeout /t 1 >nul
	<nul set /p =`r
)

if not exist "%tmp%" (
	mkdir "%tmp%"
)

powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope Process -Force"

powershell -Command "Invoke-WebRequest -Uri '%LTURL%' -OutFile '%LTPKG%'"

timeout /t 5 >nul

powershell -Command "Expand-Archive -Path '%LTPKG%' -DestinationPath '%tmp%'"

timeout /t 5 >nul

start /wait "%LTBAT%"

endlocal