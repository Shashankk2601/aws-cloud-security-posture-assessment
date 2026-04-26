# AWS Security Posture Assessment & Targeted Remediation

**Tools:** Prowler v5.22.0 · Python (Pandas) · AWS IAM · AWS CloudTrail · AWS S3  
**Framework:** CIS AWS Foundations Benchmark  
**Type:** Cloud Security Posture Management (CSPM)

> Sensitive identifiers including AWS Account IDs and resource ARNs have been redacted from all reports and screenshots.

---

## Overview

This project simulates a real-world cloud security assessment on a personal AWS account. Using Prowler — an industry-standard CSPM tool — a full baseline audit was conducted across 573 security checks, critical misconfigurations were identified and analyzed, targeted remediations were applied, and improvement was validated through a follow-up scan.

The focus areas mirror the three most commonly exploited attack surfaces in cloud breaches: **identity**, **logging visibility**, and **data exposure**.

---

## Methodology

```
Baseline Scan (573 checks)
        ↓
Python Analysis (filter HIGH/CRITICAL findings)
        ↓
Manual Risk Assessment (attacker impact per finding)
        ↓
Targeted Remediation (4 high-impact fixes)
        ↓
Re-Scan Validation (before vs after comparison)
```

---

## Phase 1 — Baseline Scan

```powershell
python -m prowler aws --output-formats csv html -o ./baseline-scan/
```

| Metric | Value |
|---|---|
| Total checks | 573 |
| Failed | 141 — 58.75% |
| Passed | 95 — 39.58% |
| Critical | 4 |
| High | 22 |

![Baseline Scan](screenshots/01_baseline_scan.png)

---

## Phase 2 — Findings Analysis

A Python script was built to reduce 240 raw findings to 10 actionable HIGH/CRITICAL issues — eliminating noise and focusing remediation effort on real risk.

```bash
python scripts/filter_findings.py
```

![Python Analysis Output](screenshots/02_python_output.png)

---

## Phase 3 — Critical Findings

> Remediation was intentionally scoped to four findings with the highest attacker impact, reflecting real-world risk prioritization.

---

### Finding 1 — Root Account MFA Disabled

| | |
|---|---|
| **Check ID** | `iam_root_mfa_enabled` |
| **Severity** | CRITICAL |
| **CIS Control** | CIS AWS 1.1 |
| **Attacker Impact** | One stolen password = full account takeover. Root has unrestricted access to all services, billing, and data with no recovery path. |

![Root MFA Finding](screenshots/03_root_mfa_finding.png)

---

### Finding 2 — IAM User with AdministratorAccess

| | |
|---|---|
| **Check ID** | `iam_user_administrator_access_policy` |
| **Severity** | CRITICAL |
| **CIS Control** | CIS AWS 1.16 |
| **Attacker Impact** | Audit user held full `AdministratorAccess` with long-lived credentials — maximum blast radius on any credential compromise. Violates least privilege. |

![IAM Finding](screenshots/04_iam_finding.png)

---

### Finding 3 — CloudTrail Not Enabled

| | |
|---|---|
| **Check ID** | `cloudtrail_multi_region_enabled` |
| **Severity** | HIGH |
| **CIS Control** | CIS AWS 3.1 |
| **Attacker Impact** | Zero API visibility across all regions. No forensic trail for incident response. An attacker could operate undetected indefinitely. |

---

### Finding 4 — S3 Block Public Access Not Enabled

| | |
|---|---|
| **Check ID** | `s3_account_level_public_access_blocks` |
| **Severity** | HIGH |
| **CIS Control** | CIS AWS 2.1 |
| **Attacker Impact** | Public S3 buckets expose data to the internet without authentication. One misconfigured bucket can cause a full data breach — the most common cloud exposure vector. |

![S3 Finding](screenshots/05_s3_finding.png)

---

## Phase 4 — Remediation

### Fix 1 — Root MFA Enabled
- Navigated to IAM → Security credentials → MFA
- Assigned Virtual MFA device via Google Authenticator

![Root MFA After](screenshots/06_root_mfa_after.png)

---

### Fix 2 — IAM Least Privilege Enforced
- Detached `AdministratorAccess` from audit user
- Attached `SecurityAudit` read-only policy

![IAM Policy Fix](screenshots/07_iam_policy_fix.png)

---

### Fix 3 — CloudTrail Enabled
- Created multi-region trail covering all AWS regions
- Configured S3 bucket for log delivery with file validation enabled

![CloudTrail Enabled](screenshots/08_cloudtrail_enabled.png)

---

### Fix 4 — S3 Public Access Blocked
- Enabled Block All Public Access at account level
- Applied bucket-level restrictions on `prowler-test-bucket`
- Verified no public ACLs or policies remain active

![S3 Block Public Access](screenshots/09_s3_block.png)

---

## Phase 5 — Re-Scan Validation

```powershell
python -m prowler aws --output-formats csv html -o ./remediation-scan/
```

| Metric | Value |
|---|---|
| Failed | 115 — 44.57% |
| Passed | 140 — 54.26% |
| Critical | 1 |
| High | 5 |

> **Note:** Total findings increased from 240 to 258. This is expected — enabling CloudTrail introduced new detectable resources into scope. Pass rate is the correct improvement metric.

![Remediation Scan](screenshots/10_remediation_scan.png)

---

## Before vs After

| Metric | Baseline | After Remediation | Change |
|---|---|---|---|
| Pass rate | 39.58% | 54.26% | **+14.68%** |
| Failed | 141 | 115 | **−26** |
| Critical | 4 | 1 | **−3** |
| High | 22 | 5 | **−17** |
| CloudTrail failures | 36 | 8 | **−28** |
| IAM failures | 18 | 15 | **−3** |

---

## CIS Benchmark Mapping

| Finding | CIS Control | Status |
|---|---|---|
| Root MFA disabled | CIS 1.1 | ✅ Remediated |
| AdministratorAccess on IAM user | CIS 1.16 | ✅ Remediated |
| CloudTrail not enabled | CIS 3.1 | ✅ Remediated |
| S3 public access not blocked | CIS 2.1 | ✅ Remediated |

---

## Scope & Limitations

Remediation was scoped to four findings with direct attacker impact. The following were out of scope:

- **AWS Organizations SCP controls** — requires Organizations setup
- **Firewall Manager** — requires Business/Enterprise support plan
- **Hardware MFA** — requires physical security key; virtual MFA applied instead

Remaining failures are enterprise-scale controls not applicable to a standalone personal account.

---

## Key Takeaways

- A default AWS account ships with critical security gaps — 4 critical findings with zero prior configuration
- Python automation cut triage time significantly — 240 findings reduced to 10 actionable priorities
- Risk-based prioritization matters more than fixing everything — 4 targeted fixes resolved 75% of critical/high severity issues
- Enabling logging services increases finding count — pass rate, not raw numbers, is the right improvement metric

---

## Project Structure

```
aws-security-posture-assessment/
├── README.md
├── scripts/
│   └── filter_findings.py
├── reports/
│   ├── baseline_security_report.txt
│   ├── remediation_security_report.txt
│   └── high_critical_findings.csv
└── screenshots/
    ├── 01_baseline_scan.png
    ├── 02_python_output.png
    ├── 03_root_mfa_finding.png
    ├── 04_iam_finding.png
    ├── 05_s3_finding.png
    ├── 06_root_mfa_after.png
    ├── 07_iam_policy_fix.png
    ├── 08_cloudtrail_enabled.png
    ├── 09_s3_block.png
    └── 10_remediation_scan.png
```

---

## Author

**Shashank** · Cybersecurity Student · Cloud Security Enthusiast  
GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*Conducted on a personal AWS account in a controlled environment for educational and portfolio purposes.*
