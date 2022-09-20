################################
##Script to disable local user account
################################
##########
##info@socfortress.co
##########
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$ErrorActionPreference = "SilentlyContinue"
$user = ($INPUT_ARRAY."parameters"."alert"."cmd").ToString()

if ((Net user $user))
{
    try{
        Net user $user /active:no
        echo  "$user was disabled" | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
    }
    catch {
        throw $_.Exception.Message
    }
}
else {
    echo  "$user was not found" | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
}
