### Sysinternals - Logonsessions [![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
### Description
## Sysinternals Logonsessions - Official documentation.

Wazuh Integration
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
----------------------------------------------------------------------------------

<p align="center">
  <a href="https://www.socfortress.co/">
<img src="https://user-images.githubusercontent.com/95670863/183437012-6ed70011-b40d-4597-8678-e3d601b6cf4d.png" alt="logo_website (1)" width="400" height="400">
  </a>
</p>
