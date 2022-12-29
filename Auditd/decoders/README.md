Use custom decoders rather than the ones provided by Wazuh. I was seeing issues during testing with their provided decoders.

Remember to exclude Wazuh's default auditd decoder and rules within the `ossec.conf` of the manager:

```
<ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml</decoder_exclude>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <rule_exclude>0365-auditd_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/software-vendors</list>
    <list>etc/lists/common-ports</list>
    <list>etc/lists/rfc-1918</list>
    <list>etc/lists/cve</list>
    <list>etc/lists/malicious-powershell</list>
    <list>etc/lists/bash_profile</list>
    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
  ```
