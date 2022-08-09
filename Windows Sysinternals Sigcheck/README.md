### Sysinternals - Sigcheck [![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
### Description
## Sysinternals Sigcheck - Official documentation.

Wazuh Integration
Wazuh Capability: Wodles Command

Log Output: Active Response Log

MITRE: T1036
Rationale: Identify executables in Users folders and run their file hashes in VirusTotal.

Edit agent configuration in Wazuh manager (shared/groups)

(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

 ```<wodle name="command">
  <disabled>no</disabled>
  <tag>sigcheck</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\sigcheck.ps1"</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
File “sigcheck.ps1”:

```################################
################################
##########
# Sigcheck will be run against all executables found in C:\Users\ and subfolders
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
# If Sigcheck already running do nothing
$ErrorActionPreference = "SilentlyContinue"
$sigcheck_running = Get-Process sigcheck -ErrorAction SilentlyContinue
if ($sigcheck_running) { Exit }
# RUN SIGCHECK AND STORE CSV
$Sigcheck_Output_CSV = c:\"Program Files"\Sysinternals\sigcheck.exe -nobanner -accepteula -u -c -v -vt -e -s C:\Users\
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$Sigcheck_Output_Array = $Sigcheck_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
$count = 0
Foreach ($item in $Sigcheck_Output_Array) {
# Discard alert if No VT Hits
 if ((-Not ($item."VTdetection" -match '^0')) -And ($item."VTdetection" -match '^\d+')) {
  echo $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
# Sleep 2 seconds every 5 runs
 if(++$count % 5 -eq 0) 
    {
        Start-Sleep -Seconds 2
    }
 }
}
```
----------------------------------------------------------------------------------

<p align="center">
  <a href="https://www.socfortress.co/">
<img src="https://user-images.githubusercontent.com/95670863/183437012-6ed70011-b40d-4597-8678-e3d601b6cf4d.png" alt="logo_website (1)" width="400" height="400">
  </a>
</p>
