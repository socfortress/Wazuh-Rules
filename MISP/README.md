[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# MISP Integration [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> Interacting With MISP’s API to detect IoCs within our Wazuh Alerts.

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)

**WAZUH - MISP INTEGRATION FOR THREAT INTEL**

<div align="center">
    <h2 align="center">Check Out OpenSecure's Tutorial</h3>
    <a href="https://www.youtube.com/watch?v=-qRMDxZpnWg">
    <img src="https://img.youtube.com/vi/-qRMDxZpnWg/0.jpg" alt="Video">
  </a>


</div>

## Intro

Wazuh manager integration with MISP for Threat Intel.


## Requirements.



* MISP instance up and running.
* MISP API AuthKey (Read-only account).
* Root CA used to sign MISP’s digital certificate. 


## Wazuh capability.

Custom integration.


## Event types / Rule groups to trigger MISP API calls.


<table>
  <tr>
   <td>Event Type
   </td>
   <td>Metadata (Win / Linux)
   </td>
   <td>Rationale
   </td>
  </tr>
  <tr>
   <td>Sysmon event 1
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  process image file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 3
   </td>
   <td>win.eventdata.destinationIp / 
<p>
eventdata.destinationIp
   </td>
   <td>Check existing IoCs in  destination IP (if public IPv4)
   </td>
  </tr>
  <tr>
   <td>Sysmon event 6
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  loaded driver file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 7
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  loaded DLL file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 15
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  downloaded file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 22
   </td>
   <td>win.eventdata.queryName
   </td>
   <td>Check existing IoCs in  queried hostname
   </td>
  </tr>
  <tr>
   <td>Wazuh Syscheck (Files)
   </td>
   <td>syscheck.sha256_after
   </td>
   <td>Check existing IoCs in  files added/modified/removed (file hash)
   </td>
  </tr>
</table>



## Wazuh Manager - Custom Integration


```
# ls -lrt /var/ossec/integrations/
total 64
-rwxr-x--- 1 root ossec  844 Jan 11 04:12 custom-misp
-rwxr-x--- 1 root ossec 8646 Jan 13 21:28 custom-misp.py
```


File “custom-misp”:


```
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```


File “custom-misp.py”:


```
#!/usr/bin/env python
# SOCFortress
# https://www.socfortress.co
# info@socfortress.co
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if MISP Alert or Error calling the API
alert_output = {}
# MISP Server Base URL
misp_base_url = "https://your_misp_instance/attributes/restSearch/"
# MISP Server API AUTH KEY
misp_api_auth_key = "your_api_authkey"
# API - HTTP Headers
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}
## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
event_type = alert["rule"]["groups"][2]
## Regex Pattern used based on SHA256 lenght (64 characters)
regex_file_hash = re.compile('\w{64}')
if event_source == 'windows':
    if event_type == 'sysmon_event1':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'true':
        sys.exit()
    elif event_type == 'sysmon_event6':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event7':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_15':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_22':
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
        except IndexError:
            sys.exit()
    else:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            send_event(alert_output, alert["agent"])
elif event_source == 'linux':
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                misp_search_value = "value:"f"{wazuh_event_param}"
                misp_search_url = ''.join([misp_base_url, misp_search_value])
                try:
                    misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
                except ConnectionError:
                    alert_output["misp"] = {}
                    alert_output["integration"] = "misp"
                    alert_output["misp"]["error"] = 'Connection Error to MISP API'
                    send_event(alert_output, alert["agent"])
                else:
                    misp_api_response = misp_api_response.json()
        # Check if response includes Attributes (IoCs)
                    if (misp_api_response["response"]["Attribute"]):
                # Generate Alert Output from MISP Response
                        alert_output["misp"] = {}
                        alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                        alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                        alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                        alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                        send_event(alert_output, alert["agent"])
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    else:
        sys.exit()
elif event_source == 'ossec' and event_type == "syscheck_entry_added":
    try:
        wazuh_event_param = alert["syscheck"]["sha256_after"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            send_event(alert_output, alert["agent"])
else:
    sys.exit()
```


Replace:



* “your_misp_instance”
* “your_api_authkey”
* “/yourpath/to/rootCA.pem”

With right values for your MISP instance. The root CA used to sign the digital certificate for the MISP instance needs to be placed in the Wazuh manager and referenced in the python script with the “verify” option in the request.

Wazuh manager config for this integration:


```
<integration>
 <name>custom-misp</name>  
 <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
 <alert_format>json</alert_format>
</integration>
```


Detection rules:


```
<group name="misp,">
 <rule id="100620" level="10">
    <field name="integration">misp</field>
    <description>MISP Events</description>
    <options>no_full_log</options>
  </rule>
<rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error connecting to API</description>
    <options>no_full_log</options>
    <group>misp_error,</group>
  </rule>
<rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,</group>
  </rule>
</group>
```



## Alerts (examples):

Sysmon Event 22 (Windows):


```
{
   "timestamp":"2022-01-12T09:12:49.276+0000",
   "rule":{
      "level":12,
      "description":"MISP - IoC found in Threat Intel - Category: Network activity, Attribute: detail43.myfirewall.org",
      "id":"100622",
      "firedtimes":2,
      "mail":true,
      "groups":[
         "misp",
         "misp_alert"
      ]
   },
   "agent":{
      "id":"020",
      "name":"WIN-7FK8M79Q5R6",
      "ip":"192.168.252.105",
      "labels":{
         "customer":"d827"
      }
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1641978769.281770800",
   "decoder":{
      "name":"json"
   },
   "data":{
      "misp":{
         "event_id":"25",
         "category":"Network activity",
         "value":"detail43.myfirewall.org",
         "type":"hostname"
      }
   },
   "location":"misp"
}
```


Sysmon Event 3 (Linux):


```
{
  "timestamp":"2022-01-12T09:29:24.925+0000",
  "rule":{
     "level":12,
     "description":"MISP - IoC found in Threat Intel - Category: Network activity, Attribute: 95.154.195.159",
     "id":"100622",
     "firedtimes":1,
     "mail":true,
     "groups":[
        "misp",
        "misp_alert"
     ]
  },
  "agent":{
     "id":"017",
     "name":"ubunutu2004vm",
     "ip":"192.168.252.191",
     "labels":{
        "customer":"d827"
     }
  },
  "manager":{
     "name":"ASHWZH01"
  },
  "id":"1641979764.292099908",
  "decoder":{
     "name":"json"
  },
  "data":{
     "misp":{
        "event_id":"25",
        "category":"Network activity",
        "value":"95.154.195.159",
        "type":"ip-dst"
     }
  },
  "location":"misp"
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
