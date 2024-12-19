$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/ventra007/sysmon-config/master/sysmonconfig-export.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$OutPath = $env:TMP
$output = $sysinternals_zip
Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile $OutPath\$sysmonconfig_file
Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-c", "$OutPath\$sysmonconfig_file") -Verb runAs
