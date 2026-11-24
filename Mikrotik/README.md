# WazuhMikrotik
- Wazuh decoders for mikrotik
- Script for monitoring Wireguard peers login/logout

Tested on RouterOS 7.12 and Wazuh 4.7.1

- Configure Wazuh manager to receive Syslog messages:
https://wazuh.com/blog/how-to-configure-rsyslog-client-to-send-events-to-wazuh/
- Configure Mikrotik to send logs to syslog server (Wazuh)
- Use WGscript.rsc script on mikrotik to monitoring wireguard peers activity and schedule it for running every 30sec
