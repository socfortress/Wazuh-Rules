<#  
.SYNOPSIS
    Uninstalls Sysmon/Sysmon64 and the Wazuh Agent.
    • Developed By SOCFortress

.NOTES
    Run from an elevated PowerShell prompt.
    Add -Transcript to keep a log in %TEMP%.
#>

[CmdletBinding()]
param(
    [switch]$Transcript,
    [string]$TranscriptPath = "$env:TEMP\sysmon_uninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# -- Privilege check -----------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run from an elevated prompt."
    exit 1
}
if ($Transcript) { Start-Transcript -Path $TranscriptPath -Append }

# -- FUNCTIONS -----------------------------------------------------------
function Uninstall-Sysmon {
    [string[]]$svcNames = @('Sysmon64','Sysmon')

    foreach ($name in $svcNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }

        $svcInfo      = Get-CimInstance Win32_Service -Filter "Name='$name'"
        $exePathFull  = ($svcInfo.PathName -replace '"','').Trim()
        $exePath      = $exePathFull.Split(' ')[0]

        if (Test-Path $exePath) {
            Write-Host "Uninstalling Sysmon via '$exePath -u force'…" -ForegroundColor Cyan
            try {
                $proc = Start-Process -FilePath $exePath `
                                       -ArgumentList '-u','force' `
                                       -NoNewWindow -Wait -PassThru
                if ($proc.ExitCode -eq 0) {
                    Write-Host "Sysmon removed cleanly (exit code 0)." -ForegroundColor Green
                } else {
                    Write-Warning "Sysmon uninstall finished with exit code $($proc.ExitCode)."
                }
            } catch {
                Write-Warning "Failed to launch Sysmon uninstall: $_"
            }
        } else {
            Write-Warning "Sysmon binary not found at '${exePath}'; proceeding to remove service entry."
        }

        sc.exe delete $name | Out-Null     # ensure orphaned service is gone
    }
}

function Uninstall-WazuhAgent {
    Write-Host "Searching for Wazuh Agent…" -ForegroundColor Cyan

    $agent = Get-CimInstance -ClassName Win32_Product `
                             -Filter "Name LIKE 'Wazuh Agent%'"

    if ($agent) {
        Write-Host "Uninstalling Wazuh Agent $($agent.Version)…" -ForegroundColor Cyan
        try {
            $result = Invoke-CimMethod -InputObject $agent -MethodName Uninstall
            switch ($result.ReturnValue) {
                0      { Write-Host "Wazuh Agent removed cleanly." -ForegroundColor Green }
                default{ Write-Warning "Uninstall completed with MSI code $($result.ReturnValue)." }
            }
        } catch {
            Write-Warning "Failed to uninstall Wazuh Agent: $_"
        }
    } else {
        Write-Host "Wazuh Agent not found in installed products." -ForegroundColor Yellow
    }

    $leftover = 'C:\Program Files (x86)\ossec-agent'
    if (Test-Path $leftover) {
        Write-Host "Removing leftover directory $leftover…" -ForegroundColor Cyan
        Remove-Item $leftover -Recurse -Force
    }
}

# -- MAIN ----------------------------------------------------------------
try {
    Uninstall-Sysmon
    Uninstall-WazuhAgent
    Write-Host "`n✅ Cleanup completed successfully." -ForegroundColor Green
} finally {
    if ($Transcript) { Stop-Transcript }
}
