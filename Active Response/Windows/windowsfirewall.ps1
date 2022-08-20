################################
##Script to add/remove destination ip to windows firewall
################################
##########
##info@socfortress.co
##########
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$ErrorActionPreference = "SilentlyContinue"
$hostip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DHCPEnabled -ne $null -and $_.DefaultIPGateway -ne $null}).IPAddress | Select-Object -First 1
$malicious_ip = ($INPUT_ARRAY."parameters"."alert"."cmd").ToString()

if ( $malicious_ip -ne '127.0.0.1' -And $malicious_ip -ne '0.0.0.0' -And $malicious_ip -ne $hostip )
{
netsh advfirewall firewall add rule name="Wazuh Block $malicious_ip" dir=out interface=any action=block remoteip=$malicious_ip/32
echo  "Malicious IP: $malicious_ip has been added to the block list" | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
}
