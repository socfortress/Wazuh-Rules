[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Windows Sysmon [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time.

_We highly recommend Sysmon for your Wazuh deployment as it provides robust amounts of endpoint telemetery. Sysmon must be installed seperately and your Wazuh Agent must be instructed to collect the Sysmon logs from Event Viewer._

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)


## [Sysmon Install Script](https://github.com/socfortress/Wazuh-Rules/blob/main/Windows_Sysmon/sysmon_install.ps1)
## [Sysmon Config Used](https://github.com/SwiftOnSecurity/sysmon-config)

## Sysmon sensor health rules (200600-200699)

`sysmon_sensor_health_rules.xml` alerts when the Sysmon sensor itself stops working. Before these rules,
these cases were silent or only raised a generic level-5 event:

| Rules | What they cover |
|---|---|
| 200600-200601 | Sysmon service crashed or stopped (SCM 7031/7034/7036) |
| 200610-200612 | Sysmon EID 255: fatal errors and driver-queue drops (rate-limited) |
| 200620-200621 | Sysmon config changed (EID 16, with the config hash) and service stopped (EID 4) |
| 200630-200666 | Output of the Sysmon watchdog wodle: restarted, restart failed, missing, stale, heartbeat, recovered and suppressed repeats |
| 200640-200641 | Failures of the daily Sysmon config reload (children of 200070) |
| 200650-200651 | PowerShell's own `__PSScriptPolicyTest_*` probe files are suppressed (they caused about one level-9 alert per PowerShell launch as SYSTEM), and a level-12 alert fires if anything ever executes such a file |
| 200665 | The watchdog's own one-time `sc.exe` calls, relabelled to level 3 |

**Do not rename this file.** Wazuh loads `etc/rules` in name order, and these rules were tested loading
after every numbered SOCFortress file. Some of them attach to rules from those files: the `if_group`
children of the EID 1 rules, and the children of 200070.

The endpoint side is **not** installed by `wazuh_socfortress_rules.sh`. That is a watchdog script and the
config-reload script in each Windows agent group's shared folder, plus two `<wodle name="command">`
blocks in that group's `agent.conf`. Load these rules on the master first, then push the endpoint pieces;
in the other order, first-run results are lost. In a cluster, update the master only, then run
`PUT /cluster/restart`.

> `wazuh_socfortress_rules.sh` moves **every** `.xml` in this repository into `/var/ossec/etc/rules/`.
> Never commit a non-rule `.xml` here (an `agent.conf` snippet, a Sysmon config, test fixtures): the
> manager would try to load it as a rules file and analysisd would fail to start.

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
