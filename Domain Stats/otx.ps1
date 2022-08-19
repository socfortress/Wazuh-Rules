################################
### Script to check event data on AlienVault OTX IoCs
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
##########
# The API Call to OTX will run the parameter passed in the call against existing IoCs
# The API response is filtered out to only get IoCs part of pulses created by the user "AlienVault"
# API Response (relevant fields) in the response converted to JSON and appended to active-responses.log
# An API key to access AlienVault OTX is required (otx.alienvault.com)
##########

# Your OTX API KEY
$otxkey = "Your_API_KEY"
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json 

#Function to Call OTX API with Params and Return Response
function ApiCall($indicator_type, $param) {
  $url = "https://otx.alienvault.com/api/v1/indicators/$indicator_type/$param/general"
  $otx_response = invoke-webrequest -URI $url -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials
  if (($otx_response.StatusCode -eq '200') -And (select-string -pattern '\"username\":\ \"AlienVault\"' -InputObject $otx_response.content))
  {
#Convert Response (JSON) to Array and remove objects
    $otx_response_array = $otx_response | ConvertFrom-Json
    $otx_response_array_trim = $otx_response_array | Select-Object sections,type,base_indicator
#Append Alert to Active Response Log
    echo  $otx_response_array_trim | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
  }
}
#Switch For Rule Group From Alert
$switch_condition = ($INPUT_ARRAY."parameters"."alert"."rule"."groups"[1]).ToString()
switch -Exact ($switch_condition){
#If Rule Group = "new_domain", Extract quieried hostname and call the API
#Alert example: {"timestamp":"2021-10-20T05:12:39.783+1100","rule":{"level":5,"description":"DNS Stats - New or Low Frequency Domain Detetcted in Query","id":"100010","firedtimes":2,"mail":false,"groups":["dnsstat","dnsstat_alert"]},"agent":{"id":"034","name":"WIN-7FK8M79Q5R6","ip":"192.168.252.105"},"manager":{"name":"tactical"},"id":"1634667159.125787496","decoder":{"name":"json"},"data":{"dnsstat":{"query":"yt3.ggpht.com","alerts":["LOW-FREQ-SCORES"],"category":"ESTABLISHED","freq_score":[4.0377,3.871],"seen_by_isc":"top1m","seen_by_web":"Wed, 16 Jan 2008 18:55:33 GMT","seen_by_you":"Mon, 18 Oct 2021 22:17:34 GMT"},"integration":"dnsstat"},"location":"dns_stats"}
"dnsstat_alert"
    {
       $indicator_type = 'hostname'
       $hostname = $INPUT_ARRAY."parameters"."alert"."data"."dnsstat"."query"
       ApiCall $indicator_type $hostname  
    break;
    } 
    
}
######################
## Wazuh Manager: Command and AR.
# <command>
#    <name>alienvault_otx</name>
#    <executable>otx.cmd</executable>
#    <timeout_allowed>no</timeout_allowed>
#  </command>
####################
# <active-response>
#   <disabled>no</disabled>
#   <level>3</level>
#   <command>alienvault_otx</command>
#   <location>local</location>
#   <rules_group>dnsstat_alert</rules_group>
#  </active-response>
