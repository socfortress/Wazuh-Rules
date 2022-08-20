[<img src="../images/logo_orange.svg" align="right" width="100" height="100" />](https://www.socfortress.co/)

# OpenCTI Integrations [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.socfortress.co/trial.html)
> Wazuh manager integration with OpenCTI for Threat Intel.

[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
[![your-own-soc-free-for-life-tier](https://img.shields.io/badge/Get%20Started-FREE%20FOR%20LIFE%20TIER-orange)](https://www.socfortress.co/trial.html)

## Intro

Wazuh manager integration with OpenCTI for Threat Intel.

Wazuh manager will consume data stored in OpenCTI via its GraphQL API endpoint.

GraphQL is a query language for APIs and a runtime for fulfilling those queries with your existing data. The API query needs to be authenticated via an Auth HTTP header and the JSON body includes a query, values and search parameters.


## Requirements.



* OpenCTI instance up and running.
* OpenCTI API Token
* Root CA used to sign OpenCTI’s digital certificate (if HTTPS enabled). 


## Wazuh capability.

Custom integration.


## Event types / Rule groups to trigger OpenCTI API calls.


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
   <td>Sysmon event 23
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  deleted file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 24
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  clipboard content file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 25
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  process file hash 
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
-rwxr-x--- 1 root ossec   844 Feb 26 10:20 custom-opencti
-rwxr-x--- 1 root ossec 21499 Feb 26 22:34 custom-opencti.py
```


File “custom-opencti”:


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


File “custom-opencti.py”:

Replace:



* “your_opencti_instance”
* “your_opencti_token”

With the right values for your OpenCTI instance. If OpenCTI is using HTTPS, the root CA used to sign the digital certificate needs to be placed in the Wazuh manager and referenced in the python script with the “verify” option in the request

Wazuh manager config for this integration:


```
<integration>
 <name>custom-opencti</name>  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
 <alert_format>json</alert_format>
</integration>
```


Detection rules:


```
<group name="threat_intel,">
 <rule id="100623" level="10">
    <field name="integration">opencti</field>
    <description>OpenCTI</description>
    <group>opencti,</group>
    <options>no_full_log</options>
  </rule>
<rule id="100624" level="5">
    <if_sid>100623</if_sid>
    <field name="opencti.error">\.+</field>
    <description>OpenCTI - Error connecting to API</description>
    <options>no_full_log</options>
    <group>opencti,opencti_error,</group>
  </rule>
<rule id="100625" level="12">
    <if_sid>100623</if_sid>
    <field name="opencti.id">\.+</field>
    <description>OpenCTI - IoC found in Threat Intel - $(opencti.value)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>
</group>
```



## OpenCTI Labels Import

Observables or Indicators in OpenCTI enriched with labels providing context will get their labels imported and displayed as part of the Wazuh alert. The integration will add an array with all the labels included as part of the API response.



![alt_text](https://github.com/juaromu/wazuh-opencti/blob/main/image1.png)




## Alerts (examples):

Sysmon Event 22 (Windows):


```
{
   "timestamp":"2022-02-27T02:56:44.681+0000",
   "rule":{
      "level":12,
      "description":"OpenCTI - IoC found in Threat Intel - sazoya.com",
      "id":"100625",
      "firedtimes":53,
      "mail":true,
      "groups":[
         "threat_intel",
         "opencti",
         "opencti_alert"
      ]
   },
   "agent":{
      "id":"020",
      "name":"WIN-7FK8M79Q5R6",
      "ip":"192.168.252.105"
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1645930604.258090811",
   "decoder":{
      "name":"json"
   },
   "data":{
      "opencti":{
         "id":"0e5e40ee-2ad3-4fc3-a9c6-a75869ea3c2e",
         "standard_id":"domain-name--40ca963a-056c-577b-b5e6-c88c30e7da75",
         "entity_type":"Domain-Name",
         "parent_types":[
            "Basic-Object",
            "Stix-Object",
            "Stix-Core-Object",
            "Stix-Cyber-Observable"
         ],
         "spec_version":"2.1",
         "created_at":"2022-02-25T00:05:01.499Z",
         "updated_at":"2022-02-25T00:05:04.019Z",
         "createdBy":{
            "id":"34c3f0f7-3087-45b5-9c6f-7dfb6916c352",
            "standard_id":"identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb",
            "entity_type":"Organization",
            "parent_types":[
               "Basic-Object",
               "Stix-Object",
               "Stix-Core-Object",
               "Stix-Domain-Object",
               "Identity"
            ],
            "spec_version":"2.1",
            "identity_class":"organization",
            "name":"AlienVault",
            "roles":"null",
            "contact_information":"null",
            "x_opencti_aliases":"null",
            "created":"2022-02-07T01:26:25.340Z",
            "modified":"2022-02-07T23:54:15.300Z",
            "objectLabel":{
               "edges":[
                  
               ]
            },
            "x_opencti_organization_type":"null",
            "x_opencti_reliability":"null"
         },
         "objectMarking":{
            "edges":[
               {
                  "node":{
                     "id":"fbfa1fc1-26e8-4058-a699-8db1811dfeed",
                     "standard_id":"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                     "entity_type":"Marking-Definition",
                     "definition_type":"TLP",
                     "definition":"TLP:WHITE",
                     "created":"2022-02-07T01:26:11.768Z",
                     "modified":"2022-02-07T01:26:11.768Z",
                     "x_opencti_order":1,
                     "x_opencti_color":"#ffffff"
                  }
               }
            ]
         },
         "objectLabel":{
            "edges":[
               {
                  "node":{
                     "id":"d4323e8a-171e-42b1-a205-446b5cee21af",
                     "value":"cobalt strike",
                     "color":"#ff7396"
                  }
               },
               {
                  "node":{
                     "id":"45b71b4c-5d6e-43d7-8c4f-518077ce900a",
                     "value":"arkime",
                     "color":"#27c7fe"
                  }
               },
               {
                  "node":{
                     "id":"25953660-7cca-49ea-a1c9-0be013a67698",
                     "value":"jarm",
                     "color":"#b2a931"
                  }
               },
               {
                  "node":{
                     "id":"b98e31ac-a269-495d-959e-7bd8b185114c",
                     "value":"ja3s",
                     "color":"#17a231"
                  }
               }
            ]
         },
         "externalReferences":{
            "edges":[
               
            ]
         },
         "observable_value":"sazoya.com",
         "x_opencti_description":"null",
         "x_opencti_score":"50",
         "indicators":{
            "edges":[
               {
                  "node":{
                     "id":"766340ed-4d34-48de-b65c-38f668534435",
                     "pattern":"[domain-name:value = 'sazoya.com']",
                     "pattern_type":"stix"
                  }
               }
            ]
         },
         "value":"sazoya.com",
         "importFiles":{
            "edges":[
               
            ]
         },
         "0":{
            "node":{
               "id":"d4323e8a-171e-42b1-a205-446b5cee21af",
               "value":"cobalt strike",
               "color":"#ff7396"
            }
         },
         "1":{
            "node":{
               "id":"45b71b4c-5d6e-43d7-8c4f-518077ce900a",
               "value":"arkime",
               "color":"#27c7fe"
            }
         },
         "2":{
            "node":{
               "id":"25953660-7cca-49ea-a1c9-0be013a67698",
               "value":"jarm",
               "color":"#b2a931"
            }
         },
         "3":{
            "node":{
               "id":"b98e31ac-a269-495d-959e-7bd8b185114c",
               "value":"ja3s",
               "color":"#17a231"
            }
         }
      },
      "integration":"opencti"
   },
   "location":"opencti"
}
```


Sysmon Event 3 (Linux):


```
{
   "timestamp":"2022-02-27T02:58:05.876+0000",
   "rule":{
      "level":12,
      "description":"OpenCTI - IoC found in Threat Intel - 105.112.50.80",
      "id":"100625",
      "firedtimes":55,
      "mail":true,
      "groups":[
         "threat_intel",
         "opencti",
         "opencti_alert"
      ]
   },
   "agent":{
      "id":"017",
      "name":"ubunutu2004vm",
      "ip":"192.168.252.191"
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1645930685.260061468",
   "decoder":{
      "name":"json"
   },
   "data":{
      "opencti":{
         "id":"e055656b-e801-4184-b59c-b1604de2fdb3",
         "standard_id":"ipv4-addr--b51a6ee8-40f9-5a72-948f-74dffbfbdc6b",
         "entity_type":"IPv4-Addr",
         "parent_types":[
            "Basic-Object",
            "Stix-Object",
            "Stix-Core-Object",
            "Stix-Cyber-Observable"
         ],
         "spec_version":"2.1",
         "created_at":"2022-02-07T02:38:08.599Z",
         "updated_at":"2022-02-07T02:38:13.647Z",
         "createdBy":{
            "id":"a7eb3bb1-d315-4732-8ae4-09882330c2a4",
            "standard_id":"identity--d1cc714c-ad82-5607-a727-babda61e797d",
            "entity_type":"Organization",
            "parent_types":[
               "Basic-Object",
               "Stix-Object",
               "Stix-Core-Object",
               "Stix-Domain-Object",
               "Identity"
            ],
            "spec_version":"2.1",
            "identity_class":"organization",
            "name":"ICS-CSIRT.io",
            "roles":"null",
            "contact_information":"null",
            "x_opencti_aliases":"null",
            "created":"2022-02-07T01:26:42.389Z",
            "modified":"2022-02-07T01:26:42.389Z",
            "objectLabel":{
               "edges":[
                  
               ]
            },
            "x_opencti_organization_type":"null",
            "x_opencti_reliability":"null"
         },
         "objectMarking":{
            "edges":[
               {
                  "node":{
                     "id":"fbfa1fc1-26e8-4058-a699-8db1811dfeed",
                     "standard_id":"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                     "entity_type":"Marking-Definition",
                     "definition_type":"TLP",
                     "definition":"TLP:WHITE",
                     "created":"2022-02-07T01:26:11.768Z",
                     "modified":"2022-02-07T01:26:11.768Z",
                     "x_opencti_order":1,
                     "x_opencti_color":"#ffffff"
                  }
               }
            ]
         },
         "objectLabel":{
            "edges":[
               {
                  "node":{
                     "id":"3017bda3-50a7-4fdd-a4da-8ee4f56ee016",
                     "value":"import",
                     "color":"#a57361"
                  }
               },
               {
                  "node":{
                     "id":"fd8f228f-a7d1-4ed8-8007-110dd1e68146",
                     "value":"business email compromise",
                     "color":"#de1f03"
                  }
               }
            ]
         },
         "externalReferences":{
            "edges":[
               
            ]
         },
         "observable_value":"105.112.50.80",
         "x_opencti_description":"Infrastructure IPs",
         "x_opencti_score":"60",
         "indicators":{
            "edges":[
               {
                  "node":{
                     "id":"8f1e842b-34b0-42b0-8203-fe7ad2e0ecdc",
                     "pattern":"[ipv4-addr:value = '105.112.50.80']",
                     "pattern_type":"stix"
                  }
               }
            ]
         },
         "value":"105.112.50.80",
         "importFiles":{
            "edges":[
               
            ]
         },
         "0":{
            "node":{
               "id":"3017bda3-50a7-4fdd-a4da-8ee4f56ee016",
               "value":"import",
               "color":"#a57361"
            }
         },
         "1":{
            "node":{
               "id":"fd8f228f-a7d1-4ed8-8007-110dd1e68146",
               "value":"business email compromise",
               "color":"#de1f03"
            }
         }
      },
      "integration":"opencti"
   },
   "location":"opencti"
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
