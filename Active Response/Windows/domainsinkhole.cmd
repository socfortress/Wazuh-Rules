:: Simple script to run Windows Firewall Block
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

pwsh.exe -executionpolicy ByPass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\domainsinkhole.ps1"

:Exit
