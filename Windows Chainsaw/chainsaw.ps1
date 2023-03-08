################################
### Script to execute F-Secure/Chainsaw - Identify Malicious activity recorded in WinEvtLogs using Sigma Rules
################################

##########
# Chainsaw will be run against all event logs found in the default location
# Output converted to JSON and appended to active-responses.log
##########

##########
# Chainsaw Version: v2.0-alpha
##########

$ErrorActionPreference = "SilentlyContinue"

# Clone or pull Sigma repo
$repo_path = "C:\Program Files\socfortress\chainsaw\sigma"
if (!(test-path $repo_path)) {
    New-Item -ItemType Directory -Force -Path $repo_path
    $env:PATH += ";C:\Program Files\Git\bin"
    git clone https://github.com/SigmaHQ/sigma.git $repo_path
} else {
    $env:PATH += ";C:\Program Files\Git\bin"
    git -C $repo_path pull
}

# Analyse events recorded in last 1 Minutes. Convert Start Date to Timestamp
$start_date = (Get-Date).AddMinutes(-1)
$from = Get-Date -Date $start_date -UFormat '+%Y-%m-%dT%H:%M:%S'

# Create Chainsaw Output Folder if it doesn't exist
$chainsaw_output = "$env:TMP\chainsaw_output"
If(!(test-path $chainsaw_output)) {
    New-Item -ItemType Directory -Force -Path $chainsaw_output
}

# Windows Sigma Path
$windows_path = "C:\Program Files\socfortress\chainsaw\sigma\rules\windows"

# Run Chainsaw and store JSONs in TMP folder
& 'C:\Program Files\socfortress\chainsaw\chainsaw.exe' hunt C:\Windows\System32\winevt -s $windows_path --mapping 'C:\Program Files\socfortress\chainsaw\mappings\sigma-event-logs-all.yml' --from $from --output $env:TMP\chainsaw_output\results.json --json --level high

# Convert JSON to new line entry for every 'group'
function Convert-JsonToNewLine($json) {
    foreach($document in $json) {
        $document.document | ConvertTo-Json -Compress -Depth 99 | foreach-object {
            [pscustomobject]@{
                group = $document.group
                kind = $document.kind
                document = $_
                name = $document.name
                timestamp = $document.timestamp
                authors = $document.authors
                level = $document.level
                source = $document.source
                status = $document.status
                falsepositives = $document.falsepositives
                id = $document.id
                logsource = $document.logsource
                references = $document.references
                tags = $document.tags
            } | ConvertTo-Json -Compress
        }
    }
}

# Convert JSONs to new line entry and append to active-responses.log
Get-ChildItem $env:TMP\chainsaw_output -Filter *.json | Foreach-Object {
    $Chainsaw_Array = Get-Content $_.FullName | ConvertFrom-Json
    Convert-JsonToNewLine $Chainsaw_Array | Out-File -Append -Encoding ascii 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
}

# Remove TMP JSON Folder
rm -r $chainsaw_output

# Output status if Sigma rules were updated
if ($LASTEXITCODE -eq 0) {
    $status_payload = @{
        group = 'sigma'
        sigma_rules = 'updated'
    } | ConvertTo-Json
    Write-Output $status_payload
}
