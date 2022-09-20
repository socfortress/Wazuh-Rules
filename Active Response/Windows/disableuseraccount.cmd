:: Simple script to run Windows Disable Local User Account
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

pwsh.exe -executionpolicy ByPass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\disableuseraccount.ps1"

:Exit
