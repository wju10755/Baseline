powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope Process -Force"
@echo off
setlocal

set tmp=C:\temp
set LTPKG=C:\temp\Warehouse_Agent_MSI_Install.zip
set LTURL=https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse_Agent_MSI_Install.zip
set LTBAT=C:\temp\install.bat

echo Starting LTAgent Setup....

if not exist "%tmp%" (
    mkdir "%tmp%"
)

timeout /t 10 /nobreak >nul

powershell -Command "Invoke-WebRequest -Uri '%LTURL%' -OutFile '%LTPKG%'"

timeout /t 5 >nul

powershell -Command "Expand-Archive -Path '%LTPKG%' -DestinationPath '%tmp%'"

timeout /t 5 >nul

start /wait "%LTBAT%"

endlocal