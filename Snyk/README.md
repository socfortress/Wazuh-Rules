[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# Snyk Integration [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> Wazuh and Snyk (snyk.io) integration to scan Docker image vulnerabilities.
> Snyk will help you find and automatically fix vulnerabilities in your code, open source dependencies, containers, and infrastructure as code. In this integration we'll use Snyk’s CLI to scan for vulnerabilities in the Docker images and all their dependencies.
> NOTE: Wazuh can use all the features available in an agent to monitor Docker servers and it can also monitor container activity. With the Snyk integration we aim at finding vulnerable packages included in the Docker images that might put the containerised applications at risk.

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)


## Snyk CLI

Snyk runs as a single binary, no installation required.

The Linux binary can be found [here](https://static.snyk.io/cli/latest/snyk-linux)

This [article](https://snyk.io/learn/docker-security-scanning/) from Snyk’s documentation explains how to use Snyk’s CLI for Docker security.

The Snyk CLI needs to be initialised before being used. In order to do that, you'll have to create and register an account in their platform ([snyk.io](https://snyk.io/)). The registration is free. More details on how to initialise the CLI [here](https://docs.snyk.io/features/snyk-cli/install-the-snyk-cli/authenticate-the-cli-with-your-account)


## Wazuh Capability:

Wodle Command configured to run periodic security scans in all Docker images used in the host.

[Jq ](https://stedolan.github.io/jq/)is used in the agent (Docker host) to filter and parse the Snyk CLI output. 

Wazuh remote commands execution must be enabled (Docker host).


## Workflow



1. Bash script to be run via wodle command will list all Docker images in the system and will run Snyk’s CLI to spot known vulnerabilities in all the packages used to build the image.
2. The JSON output will be appended to the active responses log file.
3. Detection rules in Wazuh manager will trigger alerts based on the scan results.

Remote commands execution must be enabled in the agent (Docker host), file “local_internal_options.conf”:


```
# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=1
```


Edit /var/ossec/etc/shared/**_your_linux_docker_group_**/agent.conf and add the remote command:


```
<wodle name="command">
  <disabled>no</disabled>
  <tag>snyk-scan</tag>
  <command>/usr/bin/bash /var/ossec/wodles/command/snyk_scan.sh</command>
  <interval>24h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```


Content of “snyk_scan.sh”:


```
################################
### Script to run Snyk CLI Vuln Scan on Docker Images
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
##########
# docker image list --> Obtain the list of Docker Images in the system
# The Snyk Scan is run on each image detected in the system
# Minimum Severity = Medium (change severity threshold if required)
# The scan result is appended to active-responses.log
##########
#!/bin/bash
# Static active response parameters
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Main workflow --------------------------#
#------------------------- Function to run scan on Docker Image --------------------------#
snyk_execution(){
  docker_image=$1
  /opt/snyk/snyk-linux container test "$docker_image" --json --severity-threshold=medium | jq '.vulnerabilities' | jq ".[] | {packageName, severity, id, name, version, nearestFixedInVersion, dockerfileInstruction, dockerBaseImage, nvdSeverity, publicationTime, malicious, title, cvssScore, identifiers}" | jq -c '.'
}
#------------------------- Get Docker Images and call scan function --------------------------#
docker_images_list=( $(/bin/docker image ls | tail -n +2 | awk '{ print $1 }') )
#------------------------- Append Scan Outoput to Active Response Log  --------------------------#
for docker_image in "${docker_images_list[@]}"
do
  snyk_output=$(snyk_execution $docker_image)
    if [[ $snyk_output != "" ]]
    then
        # Iterate every detected rule and append it to the LOG_FILE
        while read -r line; do
            echo $line >> ${LOG_FILE}
            sleep 0.1
        done <<< "$snyk_output"
    fi
   >> ${LOG_FILE}
  sleep 0.3
done
```


NOTE: The script above assumes that:



* The Snyk binary has been placed in “/opt/snyk/”
* The minimum severity for the vulnerabilities found is “medium”.
* Jq has been installed in the agent (used to filter and parse Snyk CLI output).

Snyk Scan detection rules:


```
<!--
  -  SNYK Docker Image Scan Rules
-->
<group name="vulnerability-detector,snyk,">
    <rule id="96600" level="10">
        <decoded_as>json</decoded_as>
        <field name="packageName">\.+</field>
        <field name="severity">medium</field>
        <description>Snyk: Alert - Vulnerable Packages - $(packageName)</description>
        <options>no_full_log</options>
    </rule>
    <rule id="96601" level="12">
        <decoded_as>json</decoded_as>
        <field name="packageName">\.+</field>
        <field name="severity">high</field>
        <description>Snyk: Alert - Vulnerable Packages - $(packageName)</description>
        <options>no_full_log</options>
    </rule>
</group>
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
