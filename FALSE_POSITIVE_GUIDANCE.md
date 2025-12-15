# False Positive Guidance for Wazuh Rules

This document identifies rules that may generate false positives in normal environments and provides guidance for tuning them based on your specific use case.

## High-Severity Rules Prone to False Positives

### File Permission Changes (Level 12)
**Rules:** 200148 (Auditd), 200259 (Osquery)
**Detection:** chmod/chown commands
**Issue:** Normal system administration triggers high-severity alerts
**Recommendation:**
- Consider lowering severity to level 5-7 for standard administrative users
- Add exclusions for known administrative scripts/automation
- Create higher-severity composite rules that trigger on multiple permission changes in short timeframe
- Use frequency thresholds to detect anomalous patterns

### File Compression (Level 10)
**Rules:** 200141-200143 (Auditd), 200254 (Osquery)
**Detection:** tar, gzip, zip, 7z commands
**Issue:** Legitimate backup and archival operations trigger alerts
**Recommendation:**
- Lower base severity to level 3-5
- Create escalation rules for:
  - Compression of sensitive directories (/etc, /var/log, user home directories)
  - Large number of files compressed in short period
  - Compression followed by network transfer
- Add exclusions for known backup scripts and times

### SystemD Operations (Level 9-12)
**Rules:** 200170 (Auditd), 200273 (Osquery)
**Detection:** systemctl daemon-reload and start commands
**Issue:** Normal service management triggers alerts
**Recommendation:**
- Lower base severity to level 3
- Create escalation rules for:
  - Systemd operations from unusual users
  - Creation of new service files followed by daemon-reload
  - Suspicious service names or paths
- Consider time-based exclusions for maintenance windows

### DLL Loading Exclusions (Level 1)
**Rule:** 900022 (Exclusion Rules)
**Detection:** Excludes ALL Microsoft-signed DLL loads
**Issue:** Overly broad exclusion may hide DLL side-loading attacks
**Recommendation:**
- Instead of blanket exclusion, be more selective:
  - Only exclude well-known system DLLs
  - Monitor for DLLs loaded from unusual locations even if Microsoft-signed
  - Alert on DLLs loaded by non-Microsoft processes
- Consider maintaining whitelist of known-good DLL/process combinations

### Process Execution in Specific Directories
**Rule:** 900019 (Exclusion Rules)
**Detection:** Excludes Sysmon Event 1 for specific directories
**Issue:** Malware could hide in excluded paths
**Recommendation:**
- Narrow exclusions to specific known-good executables rather than entire directories
- Consider hash-based exclusions for truly static binaries
- For dynamic locations, use process genealogy (parent process) instead of path exclusions

## Rules Requiring Environment-Specific Tuning

### BPFDoor Detection (Level 12)
**Rules:** 200126-200127 (Auditd), 200240-200241 (Osquery)
**Detection:** Port ranges 42xxx and 43xxx
**Issue:** Too specific - attackers using different ports will bypass detection
**Recommendation:**
- Supplement with generic iptables NAT rule monitoring
- Alert on any unexpected port redirection rules
- Combine with network connection monitoring for ports outside normal ranges

### Packetbeat DNS/HTTP/HTTPS Suppression
**Rules:** 200310-200312
**Detection:** Frequent connections to same destination
**Issue:** May suppress important C2 beaconing patterns
**Recommendation:**
- Review frequency thresholds for your environment
- Consider allowing these to fire for:
  - Destinations not in corporate DNS
  - New domains (domain age < 30 days)
  - Suspicious TLDs (.tk, .ml, etc.)

## Composite Rule Patterns for Better Detection

Instead of relying solely on individual high-severity rules, consider creating composite rules:

1. **Privilege Escalation Chain**
   - Capability discovery (getcap) → capability manipulation → privileged execution

2. **Data Exfiltration Chain**
   - File discovery → compression → network transfer

3. **Persistence Chain**
   - File creation in autostart location → systemctl daemon-reload → service start

4. **Credential Access Chain**
   - Password policy discovery → password file access → network connections

## Testing Recommendations

Before deploying rule changes in production:

1. **Enable audit mode** for rules you're testing (set to level 1-3)
2. **Monitor for 7-14 days** to establish baseline
3. **Review false positive patterns** and create targeted exclusions
4. **Gradually increase severity** as you gain confidence
5. **Document all customizations** for team knowledge sharing

## Exclusion Rule Management

Current exclusion rules (900000-series) should be:
- **Documented with justification**: Why is each exclusion necessary?
- **Regularly reviewed**: Are exclusions still needed? Are they too broad?
- **Version controlled**: Track changes to exclusions over time
- **Tested**: Ensure exclusions don't hide actual attacks

## Environment-Specific Considerations

### Development/Test Environments
- May need broader exclusions for legitimate development activities
- Consider separate rule sets with lower severity for dev environments

### Production Environments
- Stricter rules with fewer exclusions
- Higher confidence in alerts
- More aggressive incident response

### High-Security Environments
- Minimal exclusions
- Accept higher false positive rate for better security
- Dedicated SOC resources to triage alerts

---

**Last Updated:** 2025-12-15
**Applies to:** Wazuh-Rules commit d747815 and later
