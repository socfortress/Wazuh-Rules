### Sysinternals - Autoruns
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
Wazuh Rules: /var/ossec/etc/rules/win_autoruns_rules.xml

<group name="windows,">
<rule id="91550" level="12">
  <decoded_as>json</decoded_as>
  <field name="Entry">\.+</field>
  <field name="EntryLocation">\.+</field>
  <description>Windows Autoruns - VirusTotal Hit</description>
  <mitre>
   <id>T1547</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_autoruns,</group>
</rule>
<rule id="91551" level="10">
  <if_sid>91550</if_sid>
  <field name="VTdetection">Unknown</field>
  <description>Windows Autoruns - VirusTotal Unknown Signature</description>
  <mitre>
   <id>T1547</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_autoruns,</group>
</rule>
</group>
Alerts (examples) - Unknown signature in VirusTotal:

{
  "timestamp":"2021-10-02T18:08:51.174+1000",
  "rule":{
     "level":10,
     "description":"Windows Autoruns - VirusTotal Unknown Signature",
     "id":"91551",
     "mitre":{
        "id":[
           "T1547"
        ]
     },
     "firedtimes":7,
     "mail":false,
     "groups":[
        "windows",
        "windows_autoruns"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1633162131.503091800",
  "decoder":{
     "name":"json"
  },
  "data":{
     "EntryLocation":"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls",
     "Entry":"wow64win",
     "Enabled":"enabled",
     "Category":"Known DLLs",
     "Profile":"System-wide",
     "ImagePath":"c:\\windows\\syswow64\\wow64win.dll",
     "LaunchString":"wow64win.dll",
     "VTdetection":"Unknown",
     "VTpermalink":"n/a"
  },
  "location":"active-response\\active-responses.log"
}
Alerts (examples) - Signature found in VirusTotal:

 {
  "timestamp":"2021-10-02T18:08:51.065+1000",
  "rule":{
     "level":12,
     "description":"Windows Autoruns - VirusTotal Hit",
     "id":"91550",
     "mitre":{
        "id":[
           "T1547"
        ]
     },
     "firedtimes":3,
     "mail":true,
     "groups":[
        "windows",
        "windows_autoruns"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1633162131.503082888",
  "decoder":{
     "name":"json"
  },
  "data":{
     "Time":"14/04/1954 6:59 PM",
     "EntryLocation":"HKLM\\System\\CurrentControlSet\\Services",
     "Entry":"RasGre",
     "Enabled":"enabled",
     "Category":"Drivers",
     "Profile":"System-wide",
     "Description":"WAN Miniport (GRE): WAN Miniport (GRE)",
     "Signer":"Microsoft Corporation",
     "Company":"Microsoft Corporation",
     "ImagePath":"c:\\windows\\system32\\drivers\\rasgre.sys",
     "Version":"10.0.17763.1",
     "LaunchString":"\\SystemRoot\\System32\\drivers\\rasgre.sys",
     "VTdetection":"1|72",
     "VTpermalink":"https://www.virustotal.com/gui/file/d2b3066d4290ca61dd82e57dc9a1c4cbee49b4de31897b86bcd4dcdb46582f81/detection",
     "MD5":"5008678D3AC377C4D6EC605D75F56C6E",
     "SHA-1":"690EB8BB80C9A27AC33DC8AF784A7F3D678098F4",
     "PESHA-1":"B9FDF1E913C753AA2FC69AF6A2AB596946D6DC44",
     "PESHA-256":"09F88B061C6055CB5A43BE3A565227DB8447DC0151ABABE95FC6BF81AA4E6DE2",
     "SHA-256":"D2B3066D4290CA61DD82E57DC9A1C4CBEE49B4DE31897B86BCD4DCDB46582F81",
     "IMP":"3AF9DD088A7CF3AF92624C65B215F2AB"
  },
  "location":"active-response\\active-responses.log"
}
