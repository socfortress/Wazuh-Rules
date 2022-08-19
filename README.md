[<img src="images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Advanced Wazuh Detection Rules [![Awesome](https://forthebadge.com/images/badges/open-source.svg)](https://github.com/socfortress/Wazuh-Rules)
> The SOCFortress Team has commited to contributing to the Open Source community. We hope you find these rulesets helpful and robust as you work to keep your networks secure :sweat_smile:


[![Contributors][contributors-shield]][contributors-url]
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
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
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

Below are the current rules and integrations currently contained within this repo. Integrations, such as Office365, Sophos, etc. will have scripts provided within their respective folders for use. Feel free to build upon these scripts and contribute back :smile:

* [Sysmon for Windows](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon)
* [Sysmon for Linux](https://github.com/socfortress/Wazuh-Rules/tree/main/Sysmon%20Linux)
* [Office365](https://github.com/socfortress/Wazuh-Rules/tree/main/Office%20365)
* [Microsoft Defender](https://github.com/socfortress/Wazuh-Rules/tree/main/Office%20Defender)
* [Sophos](https://github.com/socfortress/Wazuh-Rules/tree/main/Sophos)
* MISP - Work In Progress
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
* Crowdstrike - WIP
* Tessian - WIP

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


1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/your_username_/Project-Name.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```js
   const API_KEY = 'ENTER YOUR API';
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Have Wazuh deployed and ingesting your logs but looking for some better detection rules? Look no further. The objective for this repo is to provide the Wazuh community with rulesets that are more accurate, descriptive, and enriched from various sources and integrations.

# FEEL FREE TO MERGE REQUEST ANY RULES THAT YOU THINK THE COMMUNITY COULD BENEFIT FROM

## Categories of various tools that this repo containes rules for are below

* Sysmon for Windows
* Sysmon for Linux
* Office365
* Microsoft Defender
* Sophos
* MISP
* Osquery
* Yara
* Suricata
* Packetbeat
* Falco
* Modsecurity
* F-Secure
* Domain Stats
* Snyk
* Autoruns
* Sigcheck
* Powershell





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
