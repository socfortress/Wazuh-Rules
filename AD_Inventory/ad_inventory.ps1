################################
### Script to Obtain AD Machines Inventory.
### Asset Criticality Assigned based on Machine Type / Role.
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
# Define Asset Criticality by Machine Type/Role (Criticality = 0 - 15)
$domain_controller_criticality = 13
$member_server_criticality = 8
$workstation_criticality = 5
# Wait time between loop execution. Avoid filling up Wazuh agent queue.
$wait_time = 0.2
#Write inventory output to Active Response File
Function WriteLogFile ([String]$LogFileText)
{
echo  $computer_json | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
}
# Get the current computer's domain name
$domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
# List all domain controllers in the domain
$domain_controllers = @(Get-ADDomainController -Filter * -Server $domainName | Select-Object Name)
# Retrieve computer objects from Active Directory
$computers = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties * | select Name, CN, Created, DistinguishedName, DNSHostName, LastLogonDate, Location, LockedOut, MemberOf, Modified, ObjectCategory, ObjectClass, OperatingSystem, OperatingSystemVersion, PrimaryGroup
# Loop thru Computers
foreach ($computer in $computers) {
#Add a normalised field for the Machine Name
    $computer | Add-Member -MemberType NoteProperty -Name "machine_name" -Value $computer.Name
#Assign asset criticality based on machine type/role
###Windows Domain Controllers

    if ($domain_controllers.Name -contains $computer.Name) {
        $computer | Add-Member -MemberType NoteProperty -Name "asset_criticality" -Value "$domain_controller_criticality"
        $computer | Add-Member -MemberType NoteProperty -Name "collection" -Value "ad_inventory"
        $computer_json = $computer | ConvertTo-Json -Depth 1 -Compress
        WriteLogFile -LogFileText $computer_json
    }
###Member Servers
    elseif ($computerOperatingSystem -like "*Server*" -and $domain_controllers.Name -notcontains $computer.Name) {
        $computer | Add-Member -MemberType NoteProperty -Name "asset_criticality" -Value "$member_server_criticality"
                $computer | Add-Member -MemberType NoteProperty -Name "collection" -Value "ad_inventory"
        $computer_json = $computer | ConvertTo-Json -Depth 1 -Compress
        WriteLogFile -LogFileText $computer_json
    }
###Workstations
    else {
        $computer | Add-Member -MemberType NoteProperty -Name "asset_criticality" -Value "$workstation_criticality"
                $computer | Add-Member -MemberType NoteProperty -Name "collection" -Value "ad_inventory"
        $computer_json = $computer | ConvertTo-Json -Depth 1 -Compress
        WriteLogFile -LogFileText $computer_json
    }
    Start-Sleep -Seconds $wait_time
}
