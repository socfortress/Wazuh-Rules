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
