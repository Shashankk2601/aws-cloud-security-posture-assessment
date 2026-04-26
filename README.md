# AWS Security Posture Assessment & Targeted Remediation (CIS Benchmark Aligned)

> Automated cloud security audit using Prowler v5.22.0 with Python-based findings analysis, risk-prioritized remediation, and CIS AWS Foundations Benchmark validation.

---

## Project Overview

This project conducts a full security assessment on a personal AWS account using Prowler — an industry-standard open-source Cloud Security Posture Management (CSPM) tool.

This workflow mirrors real-world cloud security assessments involving automated scanning, risk prioritization, targeted remediation, and validation.

The project focuses on identifying high-impact misconfigurations in identity, logging, and data exposure layers, which are commonly exploited in real-world cloud breaches.

> **Security Note:** Sensitive identifiers such as AWS Account IDs and resource ARNs have been redacted from all reports and scripts to follow security best practices.

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Prowler v5.22.0 | Cloud Security Posture Management (CSPM) |
| Python 3 + Pandas | Automated findings analysis and prioritization |
| AWS IAM | Identity and access management hardening |
| AWS CloudTrail | Audit logging and API activity monitoring |
| AWS Config | Resource configuration recording |
| AWS S3 | Log storage and public access hardening |
| CIS AWS Foundations Benchmark | Compliance framework for remediation mapping |

---

## Project Structure

```
aws-security-posture-assessment/
│
├── README.md
│
├── scripts/
│   └── filter_findings.py
│
├── reports/
│   ├── baseline_security_report.txt
│   ├── remediation_security_report.txt
│   └── high_critical_findings.csv
│
└── screenshots/
    ├── 01_baseline_scan.png
    ├── 02_python_output.png
    ├── 03_root_mfa_after.png
    ├── 04_iam_policy_fix.png
    ├── 05_cloudtrail_enabled.png
    ├── 06_config_enabled.png
    ├── 07_remediation_scan.png
    └── 08_s3_block.png
```

> **Note:** Raw Prowler CSV outputs are excluded from this repository as they contain account-specific resource identifiers. Sanitized summary reports are provided in the `reports/` folder instead.

---

## Methodology

```
AWS Account (Default Misconfigured State)
        ↓
Prowler Baseline Scan (573 checks, all regions)
        ↓
Python Script (Reduce noise, prioritize actionable risks)
        ↓
Manual Analysis (Top findings, attacker impact)
        ↓
Targeted Remediation (IAM + CloudTrail + Config + S3)
        ↓
Prowler Re-Scan (Validation)
        ↓
Before vs After Comparison (Proof of improvement)
```

---

## Phase 1 — Baseline Scan

A full Prowler scan was executed across all AWS regions covering 573 security checks.

**Command used:**
```powershell
python -m prowler aws --output-formats csv html -o ./baseline-scan/
```

**Baseline Results:**

| Metric | Value |
|---|---|
| Total checks executed | 573 |
| Total findings | 240 |
| Failed | 141 (58.75%) |
| Passed | 95 (39.58%) |
| Critical findings | 4 |
| High findings | 22 |
| Medium findings | 66 |
| Low findings | 49 |

### Baseline Scan Evidence

![Baseline Scan](screenshots/01_baseline_scan.png)

---

## Phase 2 — Python Findings Analysis

A Python script was developed to reduce noise and prioritize actionable security risks — filtering 240 raw findings down to only CRITICAL and HIGH severity issues, exporting a prioritized CSV, and generating a structured summary report.

**Command used:**
```bash
python scripts/filter_findings.py
```

**What the script does:**
- Loads Prowler CSV output
- Filters findings by `STATUS = FAIL` and `SEVERITY = critical/high`
- Exports prioritized findings to `high_critical_findings.csv`
- Generates a formatted summary report with service breakdown

### Python Analysis Output

![Python Findings Output](screenshots/02_python_output.png)

---

## Phase 3 — Critical Findings Analysis

From 240 findings, 10 unique HIGH/CRITICAL issues were identified across IAM, CloudTrail, and S3 services.

> **Note:** While multiple high and critical findings were identified, remediation was intentionally limited to high-impact identity, logging, and data exposure controls to reflect real-world risk prioritization practices.

---

### Finding 1 — Root Account MFA Disabled

| Field | Detail |
|---|---|
| Check ID | `iam_root_mfa_enabled` |
| Severity | CRITICAL |
| CIS Control | CIS AWS 1.1 |
| Risk | Root account with no MFA means complete account takeover with one stolen password — full access to all AWS services, billing, and data with no recovery path. |
| Fix Applied | Enabled Virtual MFA on root account using Google Authenticator |

---

### Finding 2 — IAM User with AdministratorAccess Policy

| Field | Detail |
|---|---|
| Check ID | `iam_user_administrator_access_policy` |
| Severity | CRITICAL |
| CIS Control | CIS AWS 1.16 |
| Risk | Audit user had full AdministratorAccess — violates least privilege principle. Long-lived credentials combined with admin access creates maximum blast radius on any credential compromise. |
| Fix Applied | Replaced AdministratorAccess with SecurityAudit read-only policy |

---

### Finding 3 — CloudTrail Not Enabled

| Field | Detail |
|---|---|
| Check ID | `cloudtrail_multi_region_enabled` |
| Severity | HIGH |
| CIS Control | CIS AWS 3.1 |
| Risk | Zero visibility into API calls, IAM changes, or login events. No forensic trail for incident response. An attacker could operate undetected indefinitely. |
| Fix Applied | Enabled multi-region CloudTrail trail with S3 log storage and log file validation |

---

### Finding 4 — AWS Config Not Enabled

| Field | Detail |
|---|---|
| Check ID | `config_recorder_all_regions_enabled` |
| Severity | MEDIUM |
| CIS Control | CIS AWS 2.5 |
| Risk | No resource change history or configuration compliance monitoring. Misconfigurations introduced over time go undetected with no audit trail. |
| Fix Applied | Enabled AWS Config recorder for all supported resources with delivery channel configured |

---

### Finding 5 — S3 Public Access Not Blocked

| Field | Detail |
|---|---|
| Check ID | `s3_account_level_public_access_blocks` |
| Severity | HIGH |
| CIS Control | CIS AWS 2.1 |
| Risk | Public S3 buckets can expose sensitive data to the internet, leading to data breaches and unauthorized access. One misconfigured bucket can expose entire datasets — one of the most common causes of cloud data breaches. |
| Fix Applied | Enabled S3 Block Public Access at both account and bucket level |

---

## Phase 4 — Remediation

### Remediation Strategy

Remediation focused on five controls covering the three most commonly exploited cloud attack surfaces:

- **Identity compromise prevention** — Root MFA eliminates the most critical account takeover vector
- **Privilege escalation prevention** — Least privilege IAM policy reduces blast radius of any credential compromise
- **Visibility and detection** — CloudTrail enables forensic capability and incident response
- **Configuration monitoring** — AWS Config establishes continuous compliance tracking
- **Data exposure prevention** — S3 public access hardening closes the most common data breach vector

Remaining findings were intentionally not remediated in this phase, as they require organization-level controls or extended service configurations beyond this project's scope.

---

### Fix 1: Root MFA
- Signed into AWS as root user
- Navigated to IAM → Security credentials → MFA
- Assigned Virtual MFA device via Google Authenticator

### Fix 2: IAM Least Privilege
- Removed AdministratorAccess managed policy from audit user
- Attached SecurityAudit read-only policy instead

### Fix 3: CloudTrail
- Created multi-region CloudTrail trail
- Configured S3 bucket for log delivery
- Enabled log file validation

### Fix 4: AWS Config
- Enabled AWS Config for all supported resources
- Configured resource recording and delivery channel

### Fix 5: S3 Public Access Hardening
- Enabled Block All Public Access at account level
- Applied bucket-level public access restrictions
- Verified no public ACLs or policies remain active

---

## Remediation Evidence

### Root MFA Enabled
![Root MFA](screenshots/03_root_mfa_after.png)

### IAM Policy Fix
![IAM Fix](screenshots/04_iam_policy_fix.png)

### CloudTrail Enabled
![CloudTrail](screenshots/05_cloudtrail_enabled.png)

### AWS Config Enabled
![Config](screenshots/06_config_enabled.png)

### S3 Public Access Blocked
![S3 Fix](screenshots/08_s3_block.png)

> Additional screenshots are available in the `/screenshots` directory.

---

## Phase 5 — After Remediation Scan

A second full Prowler scan was executed using identical parameters to validate remediation effectiveness.

**Command used:**
```powershell
python -m prowler aws --output-formats csv html -o ./remediation-scan/
```

**After Remediation Results:**

| Metric | Value |
|---|---|
| Total checks executed | 573 |
| Total findings | 258 |
| Failed | 115 (44.57%) |
| Passed | 140 (54.26%) |
| Critical findings | 1 |
| High findings | 5 |

> **Note on finding count:** Total findings increased from 240 to 258 between scans. This is expected — enabling CloudTrail and AWS Config introduced new detectable resources into scope. Pass rate is the correct metric to track improvement, which increased from 39.58% to 54.26%.

### Post-Remediation Scan

![Final Scan](screenshots/07_remediation_scan.png)

---

## Before vs After Comparison

| Metric | Baseline | After Remediation | Delta |
|---|---|---|---|
| Failed | 141 (58.75%) | 115 (44.57%) | **-26 findings** |
| Passed | 95 (39.58%) | 140 (54.26%) | **+45 checks** |
| Critical | 4 | 1 | **-3 critical** |
| High | 22 | 5 | **-17 high** |
| CloudTrail failures | 36 | 8 | **-28** |
| IAM failures | 18 | 15 | **-3** |

---

## CIS AWS Foundations Benchmark Mapping

| Finding | CIS Control | Description |
|---|---|---|
| Root MFA disabled | CIS 1.1 | Enable MFA for the root account |
| AdministratorAccess on IAM user | CIS 1.16 | Ensure IAM policies attached only to groups or roles |
| CloudTrail not enabled | CIS 3.1 | Ensure CloudTrail is enabled in all regions |
| AWS Config not enabled | CIS 2.5 | Ensure AWS Config is enabled in all regions |
| S3 public access not blocked | CIS 2.1 | Ensure S3 Block Public Access is enabled |

---

## Scope & Limitations

**Out of scope:**
- AWS Organizations-level SCP controls — requires AWS Organizations setup
- Firewall Manager (FMS) — requires AWS Business/Enterprise Support plan
- Bedrock guardrails — AI service not in use in this account
- Hardware MFA — requires physical security key; virtual MFA applied instead

**In scope:**
- IAM identity hardening (MFA, least privilege)
- CloudTrail audit logging
- AWS Config resource recording
- S3 public access hardening
- Password policy enforcement

Remaining findings were intentionally not remediated in this phase, as they require organization-level controls or extended service configurations beyond this project's scope.

---

## Key Takeaways

- A default AWS account has critical security gaps out of the box — 4 critical findings with zero prior configuration
- Automated CSPM tooling surfaces findings faster and more consistently than manual review
- Python scripting reduces noise — from 240 raw findings to 10 actionable priorities
- Remediation must be prioritized by risk impact, not finding count
- Before/after validation with measurable metrics is essential to prove remediation effectiveness
- Total finding count can increase after remediation as new services become detectable — pass rate is the correct improvement metric

---

## Author

**Shashank**
Cybersecurity Student | Cloud Security Enthusiast
GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*This project was conducted on a personal AWS account in a controlled environment for educational and portfolio purposes.*
