# Remediation Guide — Axios Supply Chain RAT (2026-03-31)

## Severity Assessment

This is a **CRITICAL** supply chain compromise. The RAT provides full remote code execution, credential theft, and persistent access. If any scanner finding is CRITICAL, treat the machine as fully compromised.

---

## Immediate Response (First 15 Minutes)

### 1. Network Isolation
- Disconnect the affected machine from the network immediately
- Block egress to `sfrclak[.]com` / `142.11.206.73` at the firewall
- Block `packages[.]npm[.]org` (note: this is NOT the real npm registry, it's a C2 domain)

### 2. Preserve Evidence
Before cleaning up, capture:
```bash
# Snapshot running processes
ps aux > /tmp/incident_ps.txt           # Linux/macOS
tasklist /v > %TEMP%\incident_ps.txt     # Windows

# Snapshot network connections
netstat -tnp > /tmp/incident_net.txt     # Linux/macOS
netstat -nao > %TEMP%\incident_net.txt   # Windows

# Copy RAT artifacts (DO NOT EXECUTE THEM)
# macOS
cp /Library/Caches/com.apple.act.mond /tmp/evidence/
# Windows
copy %PROGRAMDATA%\wt.exe %TEMP%\evidence\
copy %PROGRAMDATA%\system.bat %TEMP%\evidence\
# Linux
cp /tmp/ld.py /tmp/evidence/
```

### 3. Kill Active RAT Processes

**macOS:**
```bash
pkill -9 com.apple.act.mond
```

**Windows (PowerShell as Admin):**
```powershell
# Kill the renamed PowerShell RAT
Get-Process -Name wt -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*ProgramData*" } |
    Stop-Process -Force
```

**Linux:**
```bash
pkill -f '/tmp/ld.py'
```

---

## Cleanup — RAT Artifacts

### macOS
```bash
rm -f /Library/Caches/com.apple.act.mond
rm -f /tmp/*.scpt
rm -f "$TMPDIR/6202033"
```

### Windows (PowerShell as Admin)
```powershell
Remove-Item "$env:PROGRAMDATA\wt.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\system.bat" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\6202033.vbs" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\6202033.ps1" -Force -ErrorAction SilentlyContinue

# Remove persistence
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "MicrosoftUpdate" -ErrorAction SilentlyContinue
```

### Linux
```bash
rm -f /tmp/ld.py
rm -f "${TMPDIR:-/tmp}/6202033"
```

---

## Cleanup — npm Packages

### Step 1: Identify affected projects
Run the scanner to generate the sources map:
```bash
axios-rat-scan --sources-map npm_sources_map.yml
```

### Step 2: For each affected project

```bash
# Remove the malicious dependency
rm -rf node_modules/plain-crypto-js

# Downgrade axios to safe version
npm install axios@1.14.0    # or axios@0.30.3 for legacy

# Remove secondary vectors if present
npm uninstall @shadanai/openclaw @qqbrowser/openclaw-qbot

# Clean and reinstall
rm -rf node_modules package-lock.json
npm install

# Verify clean
axios-rat-scan /path/to/project
```

### Step 3: Pin axios in CI/CD
Add to your CI pipeline:
```bash
# Fail build if compromised versions are resolved
npx --yes axios-rat-scan || exit 1
```

---

## Credential Rotation

The RAT supports arbitrary command execution. Assume all credentials accessible from the compromised machine are stolen:

- [ ] npm tokens (`npm token revoke`)
- [ ] Git/GitHub tokens and SSH keys
- [ ] Cloud provider credentials (AWS, GCP, Azure)
- [ ] Database connection strings
- [ ] API keys in `.env` files or environment variables
- [ ] Browser saved passwords
- [ ] SSH keys (`~/.ssh/`)
- [ ] GPG keys
- [ ] CI/CD pipeline tokens (GitHub Actions, Jenkins, etc.)

---

## Post-Incident

### Verify Clean
Re-run the scanner across all drives:
```bash
axios-rat-scan --json > post_remediation_scan.json
```

### Monitor
- Watch for re-infection via CI/CD pipelines
- Monitor DNS/network logs for `sfrclak[.]com` connections
- Alert on the spoofed User-Agent: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`

### Report
- File an incident report with your security team
- If you are a maintainer of affected packages, notify downstream consumers
- Consider reporting to npm security: https://www.npmjs.com/support

---

## References

- Elastic Security Labs analysis: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- Elastic detection rules: https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections
- GitHub Security Advisory: Check https://github.com/advisories for the latest GHSA
