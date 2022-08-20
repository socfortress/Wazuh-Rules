[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Sysinternals - Logonsessions [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> If you think that when you logon to a system there's only one active logon session, this utility will surprise you. It lists the currently active logon sessions and, if you specify the -p option, the processes running in each session.

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)


## Description

[Sysinternals Logonsessions - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions)

## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log

MITRE: T1078

Edit agent configuration in Wazuh manager (shared/groups)

(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

 ```<wodle name="command">
  <disabled>no</disabled>
  <tag>logonsessions</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\logonsessions.ps1"</command>
  <interval>1h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
File “logonsessions.ps1”:

```################################
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
# RUN LOGONSESSIONS AND STORE CSV
$Sessions_Output_CSV = c:\"Program Files"\Sysinternals\logonsessions.exe  -nobanner -c -p
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$Sessions_Output_Array = $Sessions_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
Foreach ($item in $Sessions_Output_Array) {
  echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
 }
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
