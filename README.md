[<img src="images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Advanced Wazuh Detection Rules [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> The SOCFortress Team has committed to contributing to the Open Source community. We hope you find these rulesets helpful and robust as you work to keep your networks secure.


[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/socfortress/Wazuh-Rules">
    <img src="images/logo_orange.svg" alt="Logo" width="100" height="100">
    <img src="images/wazuh_logo.png" alt="Logo">
  </a>

  <h3 align="center">Advanced Wazuh Detection Rules</h3>

  <p align="center">
    Have Wazuh deployed and ingesting your logs but looking for some better detection rules? Look no further. The objective for this repo is to provide the Wazuh community with rulesets that are more accurate, descriptive, and enriched from various sources and integrations.
    <br />
    <a href="https://www.socfortress.co/index.html"><strong>Worlds First Open Source Cloud SOC »</strong></a>
    <br />
    <br />
    <a href="https://documentation.wazuh.com/current/index.html">Wazuh Docs</a>
    ·
    <a href="https://www.socfortress.co/trial.html">FREE FOR LIFE TIER</a>
    ·
    <a href="https://socfortress.medium.com/">Our Blog</a>
  </p>
</div>


<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-this-repo">About This Repo</a>
      <ul>
        <li><a href="#supported-rules-and-integrations">Supported Rules and Integrations</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About This Repo

The objective for this repo is to provide the Wazuh community with rulesets that are more accurate, descriptive, and enriched from various sources and integrations.

Here's why:
* Detection rules can be a tricky business and we believe everyone should have access to a strong and growing ruleset.
* Wazuh serves as a great EDR agent, however the default rulesets are rather laxed (in our opinion). We wanted to start building a strong repo of Wazuh rules for the community to implement themselves and expand upon as new threats arise.
* Cybersecurity is hard enough, let's work together :smile:


<p align="right">(<a href="#readme-top">back to top</a>)</p>


### Supported Rules and Integrations

Below are the current rules and integrations currently contained within this repo. Integrations, such as Office365, Trend Micro, etc. will have scripts provided within their respective folders for use. Feel free to build upon these scripts and contribute back :smile:

* [Sysmon for Windows](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon)
* [Sysmon for Linux](https://github.com/socfortress/Wazuh-Rules/tree/main/Sysmon%20Linux)
* [Office365](https://github.com/socfortress/Wazuh-Rules/tree/main/Office%20365)
* [Microsoft Defender](https://github.com/socfortress/Wazuh-Rules/tree/main/Office%20Defender)
* [Sophos](https://github.com/socfortress/Wazuh-Rules/tree/main/Sophos)
* [MISP](https://github.com/socfortress/Wazuh-Rules/tree/main/MISP)
* [Osquery](https://github.com/socfortress/Wazuh-Rules/tree/main/Osquery)
* [Yara](https://github.com/socfortress/Wazuh-Rules/tree/main/Yara)
* [Suricata](https://github.com/socfortress/Wazuh-Rules/tree/main/Suricata)
* [Packetbeat](https://github.com/socfortress/Wazuh-Rules/tree/main/Packetbeat)
* [Falco](https://github.com/socfortress/Wazuh-Rules/tree/main/Falco)
* [Modsecurity](https://github.com/socfortress/Wazuh-Rules/tree/main/Modsecurity)
* [F-Secure](https://github.com/socfortress/Wazuh-Rules/tree/main/F-Secure)
* [Domain Stats](https://github.com/socfortress/Wazuh-Rules/tree/main/Domain%20Stats)
* [Snyk](https://github.com/socfortress/Wazuh-Rules/tree/main/Snyk)
* [Autoruns](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows%20Autoruns)
* [Sigcheck](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows%20Sysinternals%20Sigcheck)
* [Powershell](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows%20Powershell)
* [Crowdstrike](https://github.com/socfortress/Wazuh-Rules/tree/main/Crowdstrike)
* [Alienvault](https://github.com/socfortress/Wazuh-Rules/tree/main/Domain%20Stats)
* Tessian - WIP

### Roadmap

Have an Integration already configured that you'd like to share? Or have an idea for an Integration that you would like help on? Feel free to add it to the Roadmap.
- [ ] Feel free to bring ideas :smile:

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

Feel free to implement all of the rules that are contained within this repo, or pick and choose as you see fit. See our Installation section below for a bash script that can be ran on your Wazuh Manager to quickly put these rules to work!

### Prerequisites

Wazuh-Manager Version 4.x Required.

[Wazuh Install Docs](https://documentation.wazuh.com/current/index.html)

[Need Assitance? - Hire SOCFortress](https://www.socfortress.co/contact_form.html)

### Installation

_You can either manually download the .xml rule files onto your Wazuh Manager or make use of our wazuh_socfortress_rules.sh script_

> :warning: **USE AT OWN RISK**: If you already have custom rules built out, there is a good chance duplicate Rule IDs will exists. This will casue the Wazuh-Manager service to fail! Ensure there are no conflicting Rule IDs and your custom rules are backed up prior to running the wazuh_socfortress_rules.sh script!


1. Become Root User
2. Run the Script
   ```sh
   curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh
   ```

![Alt Text](https://github.com/socfortress/Wazuh-Rules/blob/main/images/run%20install.gif)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b ruleCategory/DetectionRule`)
3. Commit your Changes (`git commit -m 'Add some DetectionRules'`)
4. Push to the Branch (`git push origin ruleCategory/DetectionRule`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

SOCFortress - [![LinkedIn][linkedin-shield]][linkedin-url] - info@socfortress.co

<div align="center">
  <h2 align="center">Let SOCFortress Take Your Open Source SIEM to the Next Level</h3>
  <a href="https://www.socfortress.co/contact_form.html">
    <img src="images/Email%20Banner.png" alt="Banner">
  </a>


</div>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Security is best when we work together! Huge thank you to those supporting and those future supporters!

* [Wazuh Team](https://documentation.wazuh.com/current/index.html)
* [Taylor Walton](https://www.youtube.com/channel/UC4EUQtTxeC8wGrKRafI6pZg)
* [Juan Romero](https://github.com/juaromu)

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
