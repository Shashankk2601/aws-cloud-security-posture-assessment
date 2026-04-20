# AWS Security Posture Assessment & IAM Remediation

> Automated cloud security audit using Prowler v5.22.0 with Python-based findings analysis and CIS AWS Foundations Benchmark remediation.

---

## Project Overview

This project simulates a real-world cloud security audit on an AWS account. Using Prowler — an industry-standard open-source CSPM tool — I conducted a full security assessment across 573 checks, identified critical misconfigurations, automated findings analysis using Python, applied targeted remediations, and validated improvement through a follow-up scan.

This is the same workflow used by Cloud Security Engineers and SOC analysts performing security posture assessments in production environments.

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Prowler v5.22.0 | Cloud Security Posture Management (CSPM) |
| Python 3 + Pandas | Findings analysis and report automation |
| AWS IAM | Identity and access management hardening |
| AWS CloudTrail | Audit logging and API activity monitoring |
| AWS Config | Resource configuration recording |
| AWS S3 | Log storage |
| CIS AWS Foundations Benchmark | Compliance framework for remediation mapping |

---

## Project Structure

```
aws-security-posture-assessment/
│
├── README.md
├── scripts/
│   └── filter_findings.py          # Python script to parse and prioritize findings
│
├── reports/
│   ├── baseline/
│   │   ├── prowler-output-XXXX.csv         # Raw baseline scan output
│   │   └── security_summary_report.txt     # Baseline analysis report
│   └── after/
│       ├── prowler-output-XXXX.csv         # Raw after-remediation scan output
│       └── after_remediation_report.txt    # After remediation analysis report
│
└── screenshots/
    ├── 01_baseline_scan_running.png
    ├── 02_baseline_scan_complete.png
    ├── 03_baseline_html_report.png
    ├── 04_python_analyzer_output.png
    └── 05_remediation_scan_complete.png
```

---

## Methodology

```
AWS Account (Default Misconfigured State)
        ↓
Prowler Baseline Scan (573 checks, all regions)
        ↓
Python Script (Filter + Prioritize HIGH/CRITICAL)
        ↓
Manual Analysis (Top findings, attacker impact)
        ↓
Targeted Remediation (IAM + CloudTrail + Config)
        ↓
Prowler Re-Scan (Validation)
        ↓
Before vs After Comparison (Proof of improvement)
```

---

## Phase 1 — Baseline Scan

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

![Baseline Scan Complete](screenshots/02_baseline_scan_complete.png)

---

## Phase 2 — Python Findings Analysis

A Python script was developed to automate the triage process — filtering 240 raw findings down to only CRITICAL and HIGH severity issues, exporting a prioritized CSV, and generating a structured summary report.

```bash
python scripts/filter_findings.py
```

**What the script does:**
- Loads the Prowler CSV output
- Filters findings by `STATUS = FAIL` and `SEVERITY = critical/high`
- Exports prioritized findings to `high_priority_findings.csv`
- Generates a formatted summary report

![Python Analyzer Output](screenshots/04_python_analyzer_output.png)

---

## Phase 3 — Critical Findings Analysis

From 240 findings, 10 unique HIGH/CRITICAL issues were identified. Three were selected for remediation based on direct attacker impact:

### Finding 1 — Root Account MFA Disabled
| Field | Detail |
|---|---|
| Check ID | `iam_root_mfa_enabled` |
| Severity | CRITICAL |
| CIS Control | CIS AWS 1.5 |
| Risk | Root account with no MFA = complete account takeover with one stolen password. Full access to all AWS services, billing, and data. |
| Fix Applied | Enabled Virtual MFA on root account using Google Authenticator |

---

### Finding 2 — IAM User with AdministratorAccess Policy
| Field | Detail |
|---|---|
| Check ID | `iam_user_administrator_access_policy` |
| Severity | CRITICAL |
| CIS Control | CIS AWS 1.16 |
| Risk | Audit user (`prowler-audit-user`) had full `AdministratorAccess` — violates least privilege principle. Long-lived credentials + admin access = high blast radius on compromise. |
| Fix Applied | Replaced `AdministratorAccess` with `SecurityAudit` read-only policy |

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

## Phase 4 — Remediation

### Fix 1: Root MFA
- Signed in as root user
- Navigated to IAM → Security credentials → MFA
- Assigned Virtual MFA device via Google Authenticator

### Fix 2: IAM Least Privilege
- Removed `AdministratorAccess` managed policy from `prowler-audit-user`
- Attached `SecurityAudit` read-only policy instead

### Fix 3: CloudTrail
- Created a new CloudTrail trail — all regions enabled
- Configured S3 bucket for log delivery
- Enabled log file validation

---

## Phase 5 — After Remediation Scan

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

![Remediation Scan Complete](screenshots/05_remediation_scan_complete.png)

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
| Root MFA disabled | CIS 1.5 | Enable MFA for the root account |
| AdministratorAccess on IAM user | CIS 1.16 | Ensure IAM policies are attached only to groups or roles |
| CloudTrail not enabled | CIS 3.1 | Ensure CloudTrail is enabled in all regions |
| AWS Config not enabled | CIS 2.5 | Ensure AWS Config is enabled in all regions |

---

## Scope & Limitations

**Out of scope (not applicable to standalone accounts):**
- AWS Organizations-level SCP controls — requires AWS Organizations setup
- Firewall Manager (FMS) — requires AWS Business/Enterprise Support
- Bedrock guardrails — AI service not in use
- AccessAnalyzer — requires paid tier for external access analysis

**In scope (direct security impact):**
- IAM identity hardening (MFA, least privilege)
- CloudTrail audit logging
- AWS Config resource recording
- S3 public access controls
- Password policy enforcement

Remaining failures after remediation are primarily enterprise-scale controls not applicable to a standalone personal AWS account, or require additional service dependencies beyond this project's scope.

---

## Key Takeaways

- A default AWS account has significant security gaps out of the box
- Automated tooling (Prowler) surfaces findings faster than manual review
- Python scripting can automate the triage process — reducing 240 findings to 10 actionable items
- Remediation must be prioritized by business impact, not just finding count
- Before/after validation is essential to prove fixes were effective

---

## Author

**Shashank**
Cybersecurity Student | Cloud Security Enthusiast
- GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*This project was conducted on a personal AWS account in a controlled environment for educational and portfolio purposes.*
