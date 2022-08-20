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
$malicious_domain = ($INPUT_ARRAY."parameters"."alert"."cmd").ToString()

#Resolve Malicious Domain to Localhost
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n127.0.0.1`t$malicious_domain" -Force

echo  "{Malicious Domain: $malicious_domain has been sinkholed" | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
