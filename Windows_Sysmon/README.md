# Windows Sysmon [![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
--------------------------------------------------------------
### System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time.

----------------------------------------------------------------------------------
### We highly recommend Sysmon for your Wazuh deployment as it provides robust amounts of endpoint telemetery. Sysmon must be installed seperately and your Wazuh Agent must be instructed to collect the Sysmon logs from Event Viewer.
-------------------------------------------------
### [Sysmon Install Script](https://github.com/socfortress/Wazuh-Rules/blob/main/Windows_Sysmon/sysmon_install.ps1)
### [Sysmon Config Used](https://github.com/SwiftOnSecurity/sysmon-config)

<p align="center">
<img src="https://user-images.githubusercontent.com/95670863/183437012-6ed70011-b40d-4597-8678-e3d601b6cf4d.png" alt="logo_website (1)" width="400" height="400">
</p>

[![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
