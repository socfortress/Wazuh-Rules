[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Sysinternals - Autoruns [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> This utility, which has the most comprehensive knowledge of auto-starting locations of any startup monitor, shows you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications like Internet Explorer, Explorer and media players.

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)


# Intro

Wazuh and Sysinternals integrations.

Some of the integrations included here require remote commands execution enabled in the agents.

File “local_internal_options.conf”:


```
# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=1
```

All settings and configurations in this document assume that sysinternals binaries have been placed in the folder “C:\Program Files\sysinternals”.

Review Wazuh rule IDs used for detection to discard overlapping in your own Wazuh deployment.


# 


# Sysinternals - Autoruns


## Description

[Sysinternals Autoruns - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)


## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log

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

<!-- CONTACT -->
## Need Help?

SOCFortress - [![LinkedIn][linkedin-shield]][linkedin-url] - info@socfortress.co

<div align="center">
  <h2 align="center">Let SOCFortress Professional Services Take Your Open Source SIEM to the Next Level</h3>
  <a href="https://www.socfortress.co/contact_form.html">
    <img src="../images/Email%20Banner.png" alt="Banner">
  </a>


</div>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/socfortress/Wazuh-Rules
[contributors-url]: https://github.com/socfortress/Wazuh-Rules/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/socfortress/Wazuh-Rules
[forks-url]: https://github.com/socfortress/Wazuh-Rules/network/members
[stars-shield]: https://img.shields.io/github/stars/socfortress/Wazuh-Rules
[stars-url]: https://github.com/socfortress/Wazuh-Rules/stargazers
[issues-shield]: https://img.shields.io/github/issues/othneildrew/Best-README-Template.svg?style=for-the-badge
[issues-url]: https://github.com/othneildrew/Best-README-Template/issues
[license-shield]: https://img.shields.io/badge/Help%20Desk-Help%20Desk-blue
[license-url]: https://servicedesk.socfortress.co/help/2979687893
[linkedin-shield]: https://img.shields.io/badge/Visit%20Us-www.socfortress.co-orange
[linkedin-url]: https://www.socfortress.co/
[fsecure-shield]: https://img.shields.io/badge/F--Secure-Check%20Them%20Out-blue
[fsecure-url]: https://www.f-secure.com/no/business/solutions/elements-endpoint-protection/computer
