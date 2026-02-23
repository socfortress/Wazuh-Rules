<#
PingCastle XML -> active-responses.log
- Writes single-line JSON events (one summary + one per risk rule)
- SOCFortress LLC
#>

# -------- CONFIG --------
$PingCastleXmlPath = "C:\Users\Administrator\Downloads\PingCastle_3.5.0.40\ad_hc_lab.socfortress.local.xml"

$file  = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$group = "PingCastle"

# -------- HELPERS --------
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Log-Step {
    param (
        [string]$stepName,
        [string]$status,
        [string]$details = ""
    )

    $retryCount = 0
    $maxRetries = 5
    $waitTime   = 2
    $lastError  = $null

    while ($retryCount -lt $maxRetries) {
        try {
            $log_payload = @{
                group         = $group
                step          = $stepName
                status        = $status
                details       = $details
                executionTime = $stopwatch.Elapsed.ToString()
            } | ConvertTo-Json -Compress

            $log_payload | Out-File -Append -Encoding ascii $file
            return
        } catch {
            $lastError = $_
            $retryCount++
            Start-Sleep -Seconds $waitTime
        }
    }

    Write-Host "Failed to write '$stepName' to log after $maxRetries attempts. Last Error: $lastError"
}

# -------- MAIN --------
Log-Step -stepName 'Main Script' -status 'started'

try {
    Log-Step -stepName 'Parse PingCastle XML' -status 'started' -details $PingCastleXmlPath

    if (-not (Test-Path -LiteralPath $PingCastleXmlPath)) {
        throw "PingCastle XML not found at: $PingCastleXmlPath"
    }

    [xml]$x = Get-Content -LiteralPath $PingCastleXmlPath
    $hc = $x.HealthcheckData

    Log-Step -stepName 'Parse PingCastle XML' -status 'completed'

    # ---- Build shared fields ----
    $nowUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
    $domainFqdn = [string]$hc.DomainFQDN
    $forestFqdn = [string]$hc.ForestFQDN
    $engineVer  = [string]$hc.EngineVersion
    $genDate    = [string]$hc.GenerationDate
    $netbios    = [string]$hc.NetBIOSName
    $maturity   = [int]$hc.MaturityLevel
    $privMode   = [bool]::Parse([string]$hc.IsPrivilegedMode)

    $scores = @{
        global           = [int]$hc.GlobalScore
        anomalies        = [int]$hc.AnomalyScore
        staleObjects     = [int]$hc.StaleObjectsScore
        privilegedGroups = [int]$hc.PrivilegiedGroupScore
        trusts           = [int]$hc.TrustScore
    }

    $rules = @()
    if ($hc.RiskRules -and $hc.RiskRules.HealthcheckRiskRule) {
        $rules = @($hc.RiskRules.HealthcheckRiskRule)
    }

    # ---- 1) Summary event ----
    Log-Step -stepName 'Emit Summary Event' -status 'started'

    $summary_payload = @{
        group            = $group
        eventType        = "summary"
        tool             = "PingCastle"
        search_time_utc  = $nowUtc
        engineVersion    = $engineVer
        generationDate   = $genDate
        domainFqdn       = $domainFqdn
        forestFqdn       = $forestFqdn
        netbiosName      = $netbios
        maturityLevel    = $maturity
        isPrivilegedMode = $privMode
        scores           = $scores
        riskRuleCount    = $rules.Count
        executionTime    = $stopwatch.Elapsed.ToString()
    } | ConvertTo-Json -Compress

    $summary_payload | Out-File -Append -Encoding ascii $file

    Log-Step -stepName 'Emit Summary Event' -status 'completed'

    # ---- 2) One line per risk rule ----
    Log-Step -stepName 'Emit Risk Rule Events' -status 'started' -details "riskRules=$($rules.Count)"

    foreach ($r in $rules) {
        $risk_payload = @{
            group           = $group
            eventType       = "riskRule"
            tool            = "PingCastle"
            search_time_utc = $nowUtc
            engineVersion   = $engineVer
            domainFqdn      = $domainFqdn
            forestFqdn      = $forestFqdn
            scores          = $scores
            riskId          = [string]$r.RiskId
            points          = [int]$r.Points
            category        = [string]$r.Category
            model           = [string]$r.Model
            rationale       = [string]$r.Rationale
            executionTime   = $stopwatch.Elapsed.ToString()
        } | ConvertTo-Json -Compress

        $risk_payload | Out-File -Append -Encoding ascii $file
    }

    Log-Step -stepName 'Emit Risk Rule Events' -status 'completed' -details "riskRules=$($rules.Count)"

} catch {
    $error_payload = @{
        group         = $group
        result        = 'failure'
        message       = "PingCastle script error: $_"
        executionTime = $stopwatch.Elapsed.ToString()
        xml_path      = $PingCastleXmlPath
    } | ConvertTo-Json -Compress

    $error_payload | Out-File -Append -Encoding ascii $file
    Log-Step -stepName 'Main Script' -status 'error' -details $_
}

Log-Step -stepName 'Main Script' -status 'completed'

$stopwatch.Stop()
