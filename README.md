# AWS Security Posture Assessment & Targeted Remediation
### CIS AWS Foundations Benchmark Aligned | Prowler v5.22.0

**Tools:** Prowler v5.22.0 · Python 3 (Pandas) · AWS IAM · AWS CloudTrail · AWS S3  
**Framework:** CIS AWS Foundations Benchmark · 573 checks · All AWS regions

> Sensitive identifiers including AWS Account IDs and resource ARNs have been redacted from all reports and screenshots.

---

## Results at a Glance

| Metric | Before | After | Change |
|---|---|---|---|
| Pass rate | 39.58% | 54.26% | **+14.68 pp** |
| Critical findings | 4 | 1 | **−3 (75%)** |
| High findings | 22 | 5 | **−17 (77%)** |
| Failed checks | 141 | 115 | **−26** |

Four targeted fixes. 75% of critical findings resolved.

---

## Overview

This project conducts a structured security posture assessment on a personal AWS account using Prowler — an industry-standard CSPM tool. The workflow follows a real-world cloud security engagement model: automated baseline scan → Python-based triage → risk-prioritized remediation → validated re-scan.

The assessment targets three attack surfaces most exploited in cloud breaches: **identity and access**, **audit logging**, and **data exposure**. Rather than resolving all 141 failures, remediation was deliberately scoped to four findings with the highest exploitable impact — demonstrating risk-based prioritization over checkbox compliance.

---

## Project Structure

```
aws-security-posture-assessment/
│
├── README.md
├── script/
│   └── filtered_findings.py
│
├── reports/
│   ├── baseline_security_report.txt
│   ├── remediation_security_report.txt
│   └── high_critical_findings.csv
│
└── screenshots/
    │
    ├── 01_baseline/
    │   ├── baseline_scan.png
    │   └── baseline_output.png
    │
    ├── 02_analysis/
    │   ├── python_script_execution.png
    │   └── filtered_findings_output.png
    │
    ├── 03_findings/
    │   ├── iam_misconfig.png
    │   └── s3_misconfig.png
    │
    ├── 04_remediation/
    │   ├── root_mfa_enabled.png
    │   ├── iam_policy_fixed.png
    │   ├── cloudtrail_enabled.png
    │   └── s3_public-access_blocked.png
    │
    └── 05_validation/
        ├── remediation_scan.png
        └── remediation_output.png
```

> Raw Prowler CSV outputs are excluded — they contain account-specific resource identifiers. Sanitized reports are in `reports/`.

---

## Methodology

```
Baseline Scan (573 checks, all regions)
        ↓
Python Triage (filter HIGH/CRITICAL, export prioritized findings)
        ↓
Risk Assessment (attacker impact per finding)
        ↓
Targeted Remediation (4 fixes: IAM + CloudTrail + S3)
        ↓
Re-Scan Validation (before vs after metrics)
```

Key principle: **risk-based prioritization** — maximum security improvement per unit of effort, not exhaustive remediation.

---

## Phase 1 — Baseline Scan

```powershell
python -m prowler aws --output-formats csv html -o ./baseline-scan/
```

| Metric | Value |
|---|---|
| Total checks | 573 |
| Failed | **141 (58.75%)** |
| Passed | 95 (39.58%) |
| Critical | 4 |
| High | 22 |
| Medium | 66 |
| Low | 49 |

A default AWS account with minimal resources failed nearly 60% of all checks — including four CRITICAL findings exploitable without elevated access.

<img width="1581" height="755" alt="baseline_scan" src="https://github.com/user-attachments/assets/c0f00bee-4192-45fd-83c9-d881cf2dcbb7" />

---

## Phase 2 — Python Findings Analysis

240 raw findings manually reviewed is inefficient and error-prone. A Python script automates triage — loading the Prowler CSV, filtering to CRITICAL and HIGH failures, and exporting a prioritized list with a summary report.

```bash
python scripts/filter_findings.py
```

**Result:** 240 findings → **10 actionable HIGH/CRITICAL issues**

<img width="1853" height="973" alt="python_script_execution" src="https://github.com/user-attachments/assets/58cb6a04-8162-4677-bb6c-ddd0eb2c970e" />


---

## Phase 3 — Critical Findings

---

### Finding 1 — Root Account MFA Disabled

| | |
|---|---|
| **Check ID** | `iam_root_mfa_enabled` |
| **Severity** | 🔴 CRITICAL — CIS AWS 1.1 |

The root account cannot be restricted by IAM policies and holds unrestricted access to every service, resource, and billing function. Without MFA, it is protected only by a password. A single credential compromise — through phishing, credential stuffing, or breach exposure — results in complete, irrecoverable account takeover. There is no higher-impact finding in cloud security.

![Root MFA Finding](screenshots/03_root_mfa_finding.png)

---

### Finding 2 — IAM User with AdministratorAccess

| | |
|---|---|
| **Check ID** | `iam_user_administrator_access_policy` |
| **Severity** | 🔴 CRITICAL — CIS AWS 1.16 |

The audit user held `AdministratorAccess` (`*:*`) with long-lived static access keys — maximum blast radius credentials. Any key compromise grants an attacker full administrative control instantly. An audit user requires read access only. This directly violates least privilege and represents one of the most common initial access vectors in AWS compromise scenarios.

![IAM Finding](screenshots/04_iam_finding.png)

---

### Finding 3 — CloudTrail Not Enabled

| | |
|---|---|
| **Check ID** | `cloudtrail_multi_region_enabled` |
| **Severity** | 🟠 HIGH — CIS AWS 3.1 |

No CloudTrail trail meant every API call — IAM changes, resource creation, login events — went completely unrecorded across all regions. Without logging, there is no forensic capability, no incident timeline, and no way to detect unauthorized activity. An attacker could operate freely with zero evidence trail.

---

### Finding 4 — S3 Block Public Access Disabled

| | |
|---|---|
| **Check ID** | `s3_account_level_public_access_blocks` |
| **Severity** | 🟠 HIGH — CIS AWS 2.1 |

Without account-level Block Public Access, any bucket can be inadvertently exposed via misconfigured ACLs or policies — including buckets created in the future. Public S3 contents are indexed by scanners within hours. S3 misconfiguration is responsible for some of the largest data breaches in cloud history.

![S3 Finding](screenshots/05_s3_finding.png)

---

## Phase 4 — Remediation & Evidence

---

### Fix 1 — Root MFA Enabled
- IAM → Security credentials → Assign MFA device
- Virtual MFA via Google Authenticator, verified with two consecutive OTPs

**Impact:** Eliminates single-factor root account takeover.

<img width="1917" height="910" alt="root_MFA_enabled" src="https://github.com/user-attachments/assets/63add1a1-1682-49ec-9254-67923210c30d" />


---

### Fix 2 — IAM Least Privilege Enforced
- Detached `AdministratorAccess` from audit user
- Attached `SecurityAudit` read-only policy

**Impact:** Credential blast radius reduced from full admin to read-only.

<img width="1918" height="836" alt="IAM_policy_fixed" src="https://github.com/user-attachments/assets/2e229905-31bf-4248-97c4-ddda996a3e56" />


---

### Fix 3 — CloudTrail Enabled
- Multi-region trail created covering all AWS regions
- S3 log delivery configured with file validation enabled

**Impact:** Full API visibility restored. All future account activity is now logged and tamper-evident.

<img width="1916" height="802" alt="cloudtrail_enabled" src="https://github.com/user-attachments/assets/c1ed959a-f05f-4e7d-8805-ac130332fa38" />


---

### Fix 4 — S3 Public Access Blocked
- All four account-level Block Public Access controls enabled
- Bucket-level restrictions applied and verified — no public ACLs remain

**Impact:** Data exposure vector closed at account and bucket level. Future buckets inherit restrictions by default.

<img width="1918" height="967" alt="remediation_scan" src="https://github.com/user-attachments/assets/e4094ff0-be39-4812-892e-b712b355a280" />


---

## Phase 5 — Re-Scan Validation

```powershell
python -m prowler aws --output-formats csv html -o ./remediation-scan/
```

| Metric | Value |
|---|---|
| Failed | **115 (44.57%)** |
| Passed | 140 (54.26%) |
| Critical | 1 |
| High | 5 |

> **Note:** Total findings increased from 240 to 258 — expected, not a regression. Enabling CloudTrail expanded Prowler's detectable surface. Pass rate is the correct improvement metric.

<img width="1913" height="848" alt="s3_public-access_blocked" src="https://github.com/user-attachments/assets/b04d0002-1c43-45fb-9484-1ab2d1adaac9" />
---

## Before vs After

| Metric | Baseline | Post-Remediation | Delta |
|---|---|---|---|
| Pass rate | 39.58% | 54.26% | **+14.68 pp** |
| Failed | 141 | 115 | **−26** |
| Critical | 4 | 1 | **−3 (75% reduction)** |
| High | 22 | 5 | **−17 (77% reduction)** |
| CloudTrail failures | 36 | 8 | **−28** |
| IAM failures | 18 | 15 | **−3** |

Four fixes resolved 75% of critical findings and 77% of high findings — the case for risk-based prioritization in practice.

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

The following findings were intentionally excluded — not because they were overlooked, but because they are inapplicable to a standalone personal account:

- **AWS Organizations SCP controls** — only available within an AWS Organization
- **Firewall Manager** — requires Business/Enterprise support plan
- **Hardware MFA** — requires a physical security key; virtual MFA applied instead

The 115 remaining failures are almost entirely composed of these enterprise-scale controls. All four in-scope findings — those with direct, exploitable attacker impact — were fully resolved.

---

## Key Takeaways

- **Default AWS accounts fail ~60% of security checks** without any hardening applied
- **Four fixes resolved 75% of critical risk** — risk-based prioritization outperforms exhaustive remediation
- **Python automation cut triage time significantly** — 240 findings reduced to 10 actionable priorities in seconds
- **Logging is foundational** — without CloudTrail, no other security control can be investigated after the fact
- **Finding count can increase post-remediation** — enabling services expands detectable scope; pass rate is the correct metric

---

## Author

**Shashank** · Cybersecurity Student · Cloud Security Enthusiast  
GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*Conducted on a personal AWS account in a controlled environment for educational and portfolio purposes.*
