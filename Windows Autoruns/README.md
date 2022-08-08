### Sysinternals - Autoruns [![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
### Description

[Sysinternals Autoruns - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)

### Wazuh Integration
## Wazuh Capability: Wodles Command

## Log Output: Active Response Log

## MITRE: T1547.001

Edit agent configuration in Wazuh manager (shared/groups) (/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

```<wodle name="command">
  <disabled>no</disabled>
  <tag>autoruns</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\autoruns.ps1"</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

Content of “autoruns.ps1”:

```##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
$ErrorActionPreference = "SilentlyContinue"
# If Autoruns already running do nothing
$autoruns_running = Get-Process autorunsc64 -ErrorAction SilentlyContinue
if ($autoruns_running) { Exit }
# TEMP FOLDER TO STORE AUTORUNS OUTPUT, CSV FILE
$OutPath = $env:TMP
$autorunsCsv = 'autorunsCsv.csv'
# RUN AUTORUNS AND STORE CSV
Start-Process -FilePath "c:\Program Files\Sysinternals\Autorunsc64.exe" -ArgumentList '-nobanner', '/accepteula', '-a *', '-c', '-h', '-s', '-v', '-vt' -RedirectStandardOut $OutPath\$autorunsCsv -WindowStyle hidden -Passthru -Wait
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$autorunsArray = Get-Content $OutPath\$autorunsCsv
$autorunsArray[0] = $autorunsArray[0] -replace " ", ""
$autorunsArray | Set-Content $OutPath\$autorunsCsv
$autorunsArray = Import-Csv $OutPath\$autorunsCsv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
$count = 0
Foreach ($item in $autorunsArray) {
# CHECK IF VIRUS TOTAL MATCH OR UNKNOWN HASH
    if ($item."VTdetection") {
     if (-Not ($item."VTdetection" -match '^0')) {
     echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
# Sleep 2 seconds every 5 runs
     if(++$count % 5 -eq 0) {Start-Sleep -Seconds 2}
     }
    }
}
# DETECTION RULE:
#<group name="windows,">
#<rule id="91550" level="12">
#  <decoded_as>json</decoded_as>
#  <field name="Entry">\.+</field>
#  <field name="EntryLocation">\.+</field>
#  <description>Windows Autoruns - VirusTotal Hit</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#<rule id="91551" level="10">
#  <if_sid>91550</if_sid>
#  <field name="VTdetection">Unknown</field>
#  <description>Windows Autoruns - VirusTotal Unknown Signature</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#</group>
```
----------------------------------------------------------------------------------

<p align="center">
  <a href="https://www.socfortress.co/">
<img src="https://user-images.githubusercontent.com/95670863/183437012-6ed70011-b40d-4597-8678-e3d601b6cf4d.png" alt="logo_website (1)" width="400" height="400">
  </a>
</p>
