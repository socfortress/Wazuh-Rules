################################
### Script to execute Sysinternals/Autoruns
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
$ErrorActionPreference = "SilentlyContinue"
# If Autoruns already running do nothing
$autoruns_running = Get-Process autorunsc64 -ErrorAction SilentlyContinue
if ($autoruns_running) { Exit }
# TEMP FOLDER TO STORE AUTORUNS OUTPUT, CSV FILE
$OutPath = $env:TMP
$autorunsCsv = 'autorunsCsv.csv'
# RUN AUTORUNS AND STORE CSV
Start-Process -FilePath "c:\Program Files\Sysinternals\Autorunsc64.exe" -ArgumentList '-nobanner', '/accepteula', '-a *', '-c', '-h', '-s', '-v', '-vt' -RedirectStandardOut $OutPath\$autorunsCsv -WindowStyle hidden -Passthru -Wait
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$autorunsArray = Get-Content $OutPath\$autorunsCsv
$autorunsArray[0] = $autorunsArray[0] -replace " ", ""
$autorunsArray | Set-Content $OutPath\$autorunsCsv
$autorunsArray = Import-Csv $OutPath\$autorunsCsv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
$count = 0
Foreach ($item in $autorunsArray) {
# CHECK IF VIRUS TOTAL MATCH OR UNKNOWN HASH
    if ($item."VTdetection") {
     if (-Not ($item."VTdetection" -match '^0')) {
     echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
# Sleep 2 seconds every 5 runs
     if(++$count % 5 -eq 0) {Start-Sleep -Seconds 2}
     }
    }
}
# DETECTION RULE:
#<group name="windows,">
#<rule id="91550" level="12">
#  <decoded_as>json</decoded_as>
#  <field name="Entry">\.+</field>
#  <field name="EntryLocation">\.+</field>
#  <description>Windows Autoruns - VirusTotal Hit</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#<rule id="91551" level="10">
#  <if_sid>91550</if_sid>
#  <field name="VTdetection">Unknown</field>
#  <description>Windows Autoruns - VirusTotal Unknown Signature</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#</group>
