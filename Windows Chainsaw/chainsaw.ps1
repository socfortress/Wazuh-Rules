################################
### Script to execute F-Secure/Chainsaw - Identify Malicious activitie recorded in WinEvtLogs using Sigma Rules
################################
##########
# Chainsaw will be run against all event logs found in the default location
# Output converted to JSON and appended to active-responses.log
##########
##########
# Chainsaw Version: v2.0-alpha
##########
$ErrorActionPreference = "SilentlyContinue"
#Create Chainsaw Output Folder if doesn't exist
$chainsaw_output = "$env:TMP\chainsaw_output"
If(!(test-path $chainsaw_output))
{
      New-Item -ItemType Directory -Force -Path $chainsaw_output
}
#Analyse events recorded in last 24 Hours. Convert Start Date to Timestamp
$start_date=(Get-Date).AddHours(-24)
$from=Get-Date -Date $start_date -UFormat '+%Y-%m-%dT%H:%M:%S'
# RUN CHAINSAW AND STORE CSVs in TMP folder
c:\"Program Files"\socfortress\chainsaw\chainsaw.exe hunt c:\"Program Files"\socfortress\chainsaw\sigma-rules --mapping 'C:\Program Files\socfortress\chainsaw\mappings\sigma-event-logs.yml'  --from $from C:\Windows\System32\winevt --output $env:TMP\chainsaw_output --csv
Get-ChildItem $env:TMP\chainsaw_output -Filter *.csv |
Foreach-Object {
    $count = 0
    $Chainsaw_Array = Get-Content $_.FullName | ConvertFrom-Csv
    Foreach ($item in $Chainsaw_Array) {
        echo $item | ConvertTo-Json -Compress | Out-File -width 5000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
    # Sleep 1 seconds every 5 runs - Avoid Queue Flooding.
         if(++$count % 5 -eq 0) 
            {
                Start-Sleep -Seconds 1
            }
         }
}
#Remove TMP CSV Folder
rm -r $chainsaw_output
