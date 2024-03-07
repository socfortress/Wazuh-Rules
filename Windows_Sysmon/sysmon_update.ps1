$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'
$OutPath = $env:TMP
$output = $sysinternals_zip
Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile $OutPath\$sysmonconfig_file
$serviceName = 'Sysmon64'
Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-c", "$OutPath\$sysmonconfig_file") -Verb runAs
