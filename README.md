# AWS Security Posture Assessment & Targeted Remediation
### CIS AWS Foundations Benchmark Aligned | Prowler v5.22.0

**Tools:** Prowler v5.22.0 · Python 3 (Pandas) · AWS IAM · AWS CloudTrail · AWS S3
**Framework:** CIS AWS Foundations Benchmark · 573 Checks · All AWS Regions

> Sensitive identifiers including AWS Account IDs and resource ARNs have been redacted from all reports and screenshots in accordance with security best practices.

---

## Executive Summary

Performed a CIS-aligned security assessment of an AWS environment using Prowler (573 checks), identified high-impact IAM, CloudTrail, and S3 misconfigurations, and applied targeted remediation based on attacker impact. Security pass rate improved from 39.58% to 54.26%, with critical findings reduced by 75% and high findings reduced by 77% through focused remediation and validation.

---
## Assessment Scope

**Services Assessed:** AWS IAM · AWS CloudTrail · Amazon S3

**Assessment Standard:** CIS AWS Foundations Benchmark

**Assessment Methodology:** Baseline CSPM Assessment → Risk Prioritization → Targeted Remediation → Validation Re-Assessment

**Assessment Coverage:** 573 Security Checks Across All AWS Regions

---


## Results at a Glance

| Metric | Before | After | Improvement |
|---|---|---|---|
| Pass Rate | 39.58% | 54.26% | **+14.68 pp** |
| Critical Findings | 4 | 1 | **−3 (75%)** |
| High Findings | 22 | 5 | **−17 (77%)** |
| Failed Checks | 141 | 115 | **−26** |

Four targeted remediations reduced critical findings by 75%, high findings by 77%, and improved overall security posture by 14.68 percentage points.

---

## Table of Contents

- [Assessment Workflow](#assessment-workflow)
- [Overview](#overview)
- [Project Structure](#project-structure)
- [Methodology](#methodology)
- [Phase 1 — Baseline Scan](#phase-1--baseline-scan)
- [Phase 2 — Python Findings Analysis](#phase-2--python-findings-analysis)
- [Phase 3 — Critical Findings](#phase-3--critical-findings)
- [Phase 4 — Remediation & Evidence](#phase-4--remediation--evidence)
- [Phase 5 — Re-Scan Validation](#phase-5--re-scan-validation)
- [Before vs After](#before-vs-after)
- [CIS Benchmark Mapping](#cis-benchmark-mapping)
- [Key Takeaways](#key-takeaways)
- [Scope & Limitations](#scope--limitations)

---

## Assessment Workflow

```mermaid
flowchart TD

A[AWS Environment]

A --> B[Baseline CSPM Assessment]
B --> C[573 Security Checks]

C --> D[CIS AWS Benchmark Evaluation]

D --> E[Finding Identification]
E --> F[Python-Based Prioritization]

F --> G[Identity & Access Risks]
F --> H[Logging & Monitoring Risks]
F --> I[Data Exposure Risks]

G --> J[Targeted Remediation]
H --> J
I --> J

J --> K[Validation Re-Assessment]

K --> L[Improved Security Posture]
```

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
│
├── script/
│   └── filtered_findings.py
│
├── reports/
│   ├── baseline_security_report.txt
│   ├── remediation_security_report.txt
│   └── high_priority_findings.csv
│
└── screenshots/
    ├── 01_baseline/
    │   ├── baseline_scan.png
    │   └── baseline_output.png
    │
    ├── 02_analysis/
    │   ├── python_script_execution.png
    │   └── filtered_findings_output.png
    │
    ├── 03_findings/
    │   ├── root_mfa_disabled.png
    │   ├── iam_administrator_access.png
    │   ├── cloudtrail_not_enabled.png
    │   └── s3_public_access_not_blocked.png
    │
    ├── 04_remediation/
    │   ├── root_mfa_enabled.png
    │   ├── iam_policy_fixed.png
    │   ├── cloudtrail_enabled.png
    │   └── s3_public_access_blocked.png
    │
    └── 05_validation/
        ├── remediation_scan.png
        └── remediation_output.png
```

| Folder | Purpose |
|---|---|
| `scripts/` | Python automation used for findings triage and prioritization |
| `reports/` | Sanitized assessment reports and exported findings |
| `screenshots/01_baseline/` | Initial CSPM assessment evidence |
| `screenshots/02_analysis/` | Python-based findings analysis |
| `screenshots/03_findings/` | Evidence of identified security findings |
| `screenshots/04_remediation/` | Evidence of remediation activities |
| `screenshots/05_validation/` | Validation and post-remediation assessment results |

> Raw Prowler CSV outputs are excluded — they contain account-specific resource identifiers. Sanitized reports are provided in `reports/` instead.

---

## Methodology

The assessment follows a five-phase workflow designed to mirror professional cloud security engagements — from initial discovery through validated remediation.

```
Baseline CSPM Scan (573 checks, all regions)
        ↓
CIS AWS Benchmark Evaluation
        ↓
Python-Based Risk Prioritization (HIGH/CRITICAL filter)
        ↓
Targeted Remediation (Identity · Logging · Data Exposure)
        ↓
Validation Re-Assessment (before vs after metrics)
```

Key principle: **risk-based prioritization** — maximum security improvement per unit of effort, not exhaustive remediation.

---

## Phase 1 — Baseline Scan

```powershell
python -m prowler aws --output-formats csv html -o ./baseline-scan/
```

| Metric | Value |
|---|---|
| Total Checks | 573 |
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

240 raw findings manually reviewed is inefficient and error-prone. A Python script automates triage — loading the Prowler CSV, filtering to CRITICAL and HIGH failures, and exporting a prioritized list with a structured summary report.

```bash
python scripts/filter_findings.py
```

**Result:** 240 findings → **10 actionable HIGH/CRITICAL issues**

The script applies the same filtering logic used in real SOC triage workflows — cut through volume, surface what matters, act on what has impact.

<img width="1853" height="973" alt="python_script_execution" src="https://github.com/user-attachments/assets/58cb6a04-8162-4677-bb6c-ddd0eb2c970e" />


---

## Phase 3 — Critical Findings

> Remediation was intentionally scoped to four findings with the highest attacker impact, reflecting real-world risk prioritization over exhaustive compliance.

**Supporting Evidence**

Supporting evidence for identified findings is available in `screenshots/03_findings/`:
- `root_mfa_finding.png`
- `iam_misconfig.png`
- `cloudtrail_not_enabled.png`
- `s3_misconfig.png`

---

### Finding 1 — Root Account MFA Disabled

| | |
|---|---|
| **Check ID** | `iam_root_mfa_enabled` |
| **Severity** | 🔴 Critical |
| **CIS Control** | CIS AWS 1.1 |

The root account cannot be restricted by IAM policies and holds unrestricted access to every service, resource, and billing function. Without MFA, it is protected only by a password. Compromise of a root account without MFA can result in complete administrative control of the AWS environment, making it one of the highest-impact cloud security findings.

**Remediation:** Enabled Virtual MFA on the root account.

---

### Finding 2 — IAM User with AdministratorAccess

| | |
|---|---|
| **Check ID** | `iam_user_administrator_access_policy` |
| **Severity** | 🔴 Critical |
| **CIS Control** | CIS AWS 1.16 |

The audit user held `AdministratorAccess` (`*:*`) with long-lived static access keys — maximum blast radius credentials. Any key compromise grants an attacker full administrative control instantly. An audit user requires read access only. This directly violates least privilege and represents one of the most common initial access vectors in AWS compromise scenarios.

**Remediation:** Removed AdministratorAccess and applied SecurityAudit read-only policy.

---

### Finding 3 — CloudTrail Not Enabled

| | |
|---|---|
| **Check ID** | `cloudtrail_multi_region_enabled` |
| **Severity** | 🟠 High |
| **CIS Control** | CIS AWS 3.1 |

No CloudTrail trail meant every API call — IAM changes, resource creation, login events — went completely unrecorded across all regions. Without CloudTrail, security teams lose visibility into account activity, significantly limiting detection, investigation, and forensic capabilities.

**Remediation:** Enabled multi-region CloudTrail logging with S3 log delivery and file validation.

---

### Finding 4 — S3 Block Public Access Disabled

| | |
|---|---|
| **Check ID** | `s3_account_level_public_access_blocks` |
| **Severity** | 🟠 High |
| **CIS Control** | CIS AWS 2.1 |

Without account-level Block Public Access, any bucket can be inadvertently exposed via misconfigured ACLs or policies — including buckets created in the future. Public S3 contents are indexed by third-party scanners within hours. S3 misconfiguration is responsible for some of the largest data breaches in cloud history.

**Remediation:** Enabled account-level Block Public Access across all four controls.

---

## Phase 4 — Remediation & Evidence

Remediation was ordered by attack surface priority: **identity first, logging second, data exposure third** — the same sequence used in real incident response.

---

### Fix 1 — Root MFA Enabled
- IAM → Security credentials → Assign MFA device
- Virtual MFA configured via Google Authenticator
- Verified with two consecutive OTPs

**Impact:** Eliminates single-factor root account takeover.

<img width="1917" height="910" alt="root_MFA_enabled" src="https://github.com/user-attachments/assets/63add1a1-1682-49ec-9254-67923210c30d" />

---

### Fix 2 — IAM Least Privilege Enforced
- Detached `AdministratorAccess` from audit user
- Attached `SecurityAudit` read-only policy

**Impact:** Credential blast radius reduced from full admin to read-only access.

<img width="1918" height="836" alt="IAM_policy_fixed" src="https://github.com/user-attachments/assets/2e229905-31bf-4248-97c4-ddda996a3e56" />

---

### Fix 3 — CloudTrail Enabled
- Multi-region trail created covering all AWS regions
- S3 log delivery configured with file validation enabled

**Impact:** Full API visibility restored. All account activity is now logged and tamper-evident.

<img width="1916" height="802" alt="cloudtrail_enabled" src="https://github.com/user-attachments/assets/c1ed959a-f05f-4e7d-8805-ac130332fa38" />

---

### Fix 4 — S3 Public Access Blocked
- All four account-level Block Public Access controls enabled
- Bucket-level restrictions applied and verified
- No public ACLs or policies remain active

**Impact:** Data exposure vector closed at both account and bucket level. Future buckets inherit restrictions by default.

<img width="1913" height="848" alt="s3_public-access_blocked" src="https://github.com/user-attachments/assets/b04d0002-1c43-45fb-9484-1ab2d1adaac9" />

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

> **Note on finding count:** Total findings increased from 240 to 258 — expected, not a regression. Enabling CloudTrail introduced new detectable resources into Prowler's scope. Pass rate is the correct improvement metric.

<img width="1918" height="967" alt="remediation_scan" src="https://github.com/user-attachments/assets/e4094ff0-be39-4812-892e-b712b355a280" />

---

## Before vs After

| Metric | Baseline | Post-Remediation | Delta |
|---|---|---|---|
| Pass Rate | 39.58% | 54.26% | **+14.68 pp** |
| Failed | 141 | 115 | **−26** |
| Critical | 4 | 1 | **−3 (75% reduction)** |
| High | 22 | 5 | **−17 (77% reduction)** |
| CloudTrail Failures | 36 | 8 | **−28** |
| IAM Failures | 18 | 15 | **−3** |

Four fixes resolved 75% of critical findings and 77% of high findings — the case for risk-based prioritization in practice.

---

## CIS Benchmark Mapping

| Finding | CIS Control | Description | Status |
|---|---|---|---|
| Root MFA disabled | CIS 1.1 | Enable MFA for the root account | ✅ Remediated |
| AdministratorAccess on IAM user | CIS 1.16 | Ensure IAM policies are attached only to groups or roles | ✅ Remediated |
| CloudTrail not enabled | CIS 3.1 | Ensure CloudTrail is enabled in all regions | ✅ Remediated |
| S3 public access not blocked | CIS 2.1 | Ensure S3 Block Public Access is configured | ✅ Remediated |

---

## Key Takeaways

- **Default AWS accounts fail ~60% of security checks** without any prior hardening
- **Four fixes resolved 75% of critical risk** — risk-based prioritization outperforms exhaustive remediation
- **Python automation cut triage time significantly** — 240 findings reduced to 10 actionable priorities
- **Logging is foundational** — without CloudTrail, no other security control can be investigated after the fact
- **Finding count can increase post-remediation** — enabling services expands detectable scope; pass rate is the correct metric

---

## Scope & Limitations

The following findings were intentionally excluded — not because they were overlooked, but because they are inapplicable to a standalone personal account:

- **AWS Organizations SCP controls** — only available within an AWS Organization. A standalone account cannot implement these regardless of configuration effort.
- **Firewall Manager (FMS)** — requires AWS Business or Enterprise Support subscription. Not available on personal accounts.
- **Hardware MFA** — CIS recommends hardware MFA for root accounts. Virtual MFA was applied instead, which satisfies the control intent for a personal account environment.
- **AccessAnalyzer, Bedrock guardrails, CloudWatch metric filters** — legitimate production controls that fall outside the identity, logging, and data exposure scope of this assessment.

The 115 remaining failures post-remediation are almost entirely composed of these enterprise-scale controls. All four in-scope findings — those with direct, exploitable attacker impact — were fully resolved.

---
## Skills Demonstrated

### Cloud Security
- Cloud Security Posture Management (CSPM)
- AWS IAM Security Controls
- AWS CloudTrail Configuration & Validation
- Amazon S3 Security Hardening
- CIS AWS Foundations Benchmark Assessment

### Security Analysis
- Security Findings Triage
- Risk-Based Prioritization
- Misconfiguration Analysis
- Security Validation & Reporting

### Automation
- Python Data Analysis
- CSV Processing & Findings Filtering
- Security Assessment Reporting

### Security Operations Mindset
- Attack Surface Identification
- Risk Assessment
- Remediation Planning
- Security Posture Improvement Measurement
  
## Author

**Shashank** · Cybersecurity Student · Cloud Security Enthusiast
GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*Conducted on a personal AWS account in a controlled environment for educational and portfolio purposes.*
