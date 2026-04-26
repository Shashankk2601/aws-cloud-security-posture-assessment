# AWS Security Posture Assessment & Targeted Remediation
### CIS AWS Foundations Benchmark Aligned | Prowler v5.22.0

**Tools:** Prowler v5.22.0 · Python 3 (Pandas) · AWS IAM · AWS CloudTrail · AWS S3  
**Framework:** CIS AWS Foundations Benchmark  
**Scan Coverage:** 573 checks across all AWS regions  
**Assessment Type:** Cloud Security Posture Management (CSPM)

> **Security Note:** All sensitive identifiers including AWS Account IDs, User IDs, and resource ARNs have been redacted from reports, scripts, and screenshots in accordance with security best practices.

---

## Overview

Cloud environments are misconfigured by default. A freshly created AWS account — even one with minimal resources — carries significant security debt across identity management, audit logging, and data exposure. Most organizations discover these gaps only after a breach, not before.

This project conducts a structured, end-to-end security posture assessment on a personal AWS account using **Prowler** — an open-source Cloud Security Posture Management (CSPM) tool trusted by security teams globally. The assessment follows the same core workflow used in real-world cloud security engagements:

1. **Automated baseline scanning** across all services and regions
2. **Risk-prioritized findings analysis** using a custom Python script
3. **Targeted remediation** focused on the highest-impact misconfigurations
4. **Validation** through a follow-up scan with measurable before/after metrics

The project focuses on three attack surfaces most commonly exploited in cloud breaches: **identity and access management**, **audit logging and visibility**, and **data exposure via storage misconfiguration**. Rather than attempting to resolve all 141 failures, remediation was deliberately scoped to four findings that deliver the highest security improvement per unit of effort — a decision-making approach that reflects real security operations.

This is not a checklist exercise. It is a demonstration of how security analysts think: identify what matters, understand the risk, fix what has impact, and prove it worked.

---

## Project Structure

```
aws-security-posture-assessment/
│
├── README.md
│
├── scripts/
│   └── filter_findings.py          # Python triage automation script
│
├── reports/
│   ├── baseline_security_report.txt       # Baseline findings summary
│   ├── remediation_security_report.txt    # Post-remediation findings summary
│   └── high_critical_findings.csv         # Filtered HIGH/CRITICAL export
│
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

> **Note:** Raw Prowler CSV outputs are excluded from this repository. They contain account-specific resource identifiers not suitable for public repositories. Sanitized summary reports are provided in `reports/` instead.

---

## Methodology

The assessment follows a five-phase workflow designed to mirror professional cloud security engagements — from initial discovery through validated remediation.

```
AWS Account (Default, Minimally Configured)
            ↓
  Phase 1 — Baseline Scan
  Prowler executes 573 checks across all regions
            ↓
  Phase 2 — Python Findings Analysis
  Script filters noise, isolates HIGH/CRITICAL findings
            ↓
  Phase 3 — Risk Assessment
  Each finding evaluated for attacker impact and exploitability
            ↓
  Phase 4 — Targeted Remediation
  Four high-impact fixes applied across IAM, CloudTrail, and S3
            ↓
  Phase 5 — Re-Scan Validation
  Second Prowler scan confirms improvement with measurable metrics
```

The key principle throughout is **risk-based prioritization** — not all findings are equal, and not all findings warrant immediate action. The goal is maximum security improvement with minimum operational disruption.

---

## Phase 1 — Baseline Scan

A full Prowler scan was executed against the AWS account with no prior hardening, covering all supported services across every enabled region. This establishes the true security baseline — what the account looks like before any intervention.

```powershell
python -m prowler aws --output-formats csv html -o ./baseline-scan/
```

**Baseline Results:**

| Metric | Value |
|---|---|
| Total checks executed | 573 |
| Total findings recorded | 240 |
| **Failed** | **141 (58.75%)** |
| Passed | 95 (39.58%) |
| Manual review required | 4 |
| Critical severity failures | 4 |
| High severity failures | 22 |
| Medium severity failures | 66 |
| Low severity failures | 49 |

Nearly 60% of all checks failed on a default account. Of these, 26 findings were classified as HIGH or CRITICAL — representing genuine, exploitable risk requiring immediate attention.

![Baseline Scan Complete](screenshots/01_baseline_scan.png)

---

## Phase 2 — Python Findings Analysis

Manual review of 240 findings is inefficient and error-prone. A Python script was developed to automate the triage process — loading the raw Prowler CSV, filtering to only CRITICAL and HIGH severity failures, and exporting a prioritized findings list alongside a structured summary report.

This mirrors how security operations teams use scripting to cut through alert volume and surface what actually needs attention.

```bash
python scripts/filter_findings.py
```

**Script logic:**
- Loads Prowler output CSV (semicolon-delimited)
- Filters: `STATUS == FAIL` AND `SEVERITY in [critical, high]`
- Exports prioritized findings to `high_critical_findings.csv`
- Generates a formatted executive summary report

**Output:** 240 raw findings → **10 actionable HIGH/CRITICAL issues**

This reduction allows remediation effort to be focused precisely where it matters rather than spread thin across low-impact findings.

![Python Script Output](screenshots/02_python_output.png)

---

## Phase 3 — Critical Findings Analysis

From 10 HIGH/CRITICAL findings, four were selected for remediation based on three criteria: severity, exploitability without additional access, and direct business impact. Each finding is assessed below with its attacker impact clearly stated.

---

### Finding 1 — Root Account MFA Disabled

| Field | Detail |
|---|---|
| **Check ID** | `iam_root_mfa_enabled` |
| **Severity** | 🔴 CRITICAL |
| **CIS Control** | CIS AWS 1.1 |
| **Service** | AWS IAM |

**Risk:** The root account is the single most privileged identity in any AWS environment — it cannot be restricted by IAM policies and has unrestricted access to every service, resource, and billing function. Without MFA, the account is protected only by a password. A single credential compromise — through phishing, credential stuffing, or data breach exposure — results in complete, irrecoverable account takeover. There is no higher-impact finding in cloud security.

![Root MFA Finding](screenshots/03_root_mfa_finding.png)

---

### Finding 2 — IAM User with AdministratorAccess Policy

| Field | Detail |
|---|---|
| **Check ID** | `iam_user_administrator_access_policy` |
| **Severity** | 🔴 CRITICAL |
| **CIS Control** | CIS AWS 1.16 |
| **Service** | AWS IAM |

**Risk:** The audit user (`prowler-audit-user`) was found with the AWS-managed `AdministratorAccess` policy attached — granting `*:*` permissions across all services and resources. Combined with long-lived static access keys (no MFA, no rotation), this represents a maximum blast radius credential: any compromise of the access key immediately grants an attacker full administrative control. This directly violates the principle of least privilege. An audit user needs read access — nothing more.

![IAM Finding](screenshots/04_iam_finding.png)

---

### Finding 3 — CloudTrail Not Enabled

| Field | Detail |
|---|---|
| **Check ID** | `cloudtrail_multi_region_enabled` |
| **Severity** | 🟠 HIGH |
| **CIS Control** | CIS AWS 3.1 |
| **Service** | AWS CloudTrail |

**Risk:** With no CloudTrail trail configured, every API call made against this account — including IAM changes, resource creation, login events, and policy modifications — goes completely unrecorded. This eliminates any possibility of forensic investigation, incident timeline reconstruction, or detection of unauthorized activity. An attacker who gains access can operate freely, create backdoor accounts, exfiltrate data, and escalate privileges with zero audit trail. No logging means no detection, no response, and no evidence.

---

### Finding 4 — S3 Block Public Access Not Enabled

| Field | Detail |
|---|---|
| **Check ID** | `s3_account_level_public_access_blocks` |
| **Severity** | 🟠 HIGH |
| **CIS Control** | CIS AWS 2.1 |
| **Service** | AWS S3 |

**Risk:** S3 misconfiguration is responsible for some of the largest data breaches in cloud history. Without account-level Block Public Access enabled, any bucket — including those created in the future — can be inadvertently made public through misconfigured ACLs or bucket policies. The risk is compounded by the fact that S3 bucket contents are often indexed by search engines and third-party scanners within hours of being made public. A single misconfigured bucket can expose entire datasets with no authentication required.

![S3 Finding](screenshots/05_s3_finding.png)

---

## Phase 4 — Remediation & Evidence

Remediation was scoped to the four findings above. Each fix was applied manually through the AWS Console and validated visually. The approach prioritizes **identity hardening first**, followed by **logging restoration**, then **data exposure prevention** — the same order of operations used in real incident response.

---

### Fix 1 — Root Account MFA Enabled

**Steps taken:**
- Authenticated as root using account email credentials
- Navigated to IAM → Security credentials → Multi-factor authentication
- Assigned a Virtual MFA device using Google Authenticator
- Verified with two consecutive OTP codes to confirm binding

**Security impact:** Eliminates single-factor account takeover as an attack vector for the most privileged identity in the account.

![Root MFA After](screenshots/06_root_mfa_after.png)

---

### Fix 2 — IAM Least Privilege Enforced

**Steps taken:**
- Navigated to IAM → Users → prowler-audit-user → Permissions
- Detached `AdministratorAccess` AWS-managed policy
- Attached `SecurityAudit` read-only policy — grants visibility required for Prowler scanning without write or administrative permissions

**Security impact:** Reduces credential blast radius from full account compromise to read-only access. Aligns the audit user's permissions with the actual access it requires.

![IAM Policy Fix](screenshots/07_iam_policy_fix.png)

---

### Fix 3 — CloudTrail Enabled (Multi-Region)

**Steps taken:**
- Created a new CloudTrail trail with multi-region coverage enabled
- Configured a dedicated S3 bucket for log delivery
- Enabled log file validation to detect tampering or deletion of log files
- Verified trail status shows active logging

**Security impact:** Restores full API visibility across all regions. Every subsequent action in the account — including future misconfigurations or unauthorized access — will now be recorded and available for forensic review.

![CloudTrail Enabled](screenshots/08_cloudtrail_enabled.png)

---

### Fix 4 — S3 Block Public Access Enabled

**Steps taken:**
- Navigated to S3 → Block Public Access settings (account level)
- Enabled all four Block Public Access controls:
  - Block public ACLs
  - Ignore public ACLs
  - Block public bucket policies
  - Restrict public buckets
- Applied equivalent controls at individual bucket level for `prowler-test-bucket`
- Verified no public ACLs or policies remain active

**Security impact:** Closes the most common unintentional data exposure vector at both the account and bucket level. Any future bucket created in this account inherits these restrictions by default.

![S3 Block Public Access](screenshots/09_s3_block.png)

---

## Phase 5 — Re-Scan Validation

A second full Prowler scan was executed using identical parameters to measure the impact of remediation. The results confirm meaningful improvement across every tracked metric.

```powershell
python -m prowler aws --output-formats csv html -o ./remediation-scan/
```

| Metric | Value |
|---|---|
| Total checks executed | 573 |
| Total findings recorded | 258 |
| **Failed** | **115 (44.57%)** |
| Passed | 140 (54.26%) |
| Critical severity failures | 1 |
| High severity failures | 5 |

> **On the finding count increase:** Total findings rose from 240 to 258 between scans. This is expected and not a regression. Enabling CloudTrail introduced new detectable resources into Prowler's scope, increasing the total surface area assessed. The correct improvement metric is **pass rate**, which increased from 39.58% to 54.26% — a 14.68 percentage point gain.

![Remediation Scan Complete](screenshots/10_remediation_scan.png)

---

## Before vs After Comparison

| Metric | Baseline | Post-Remediation | Delta |
|---|---|---|---|
| Pass rate | 39.58% | 54.26% | **+14.68 pp** |
| Failed findings | 141 | 115 | **−26** |
| Critical findings | 4 | 1 | **−3 (75% reduction)** |
| High findings | 22 | 5 | **−17 (77% reduction)** |
| CloudTrail failures | 36 | 8 | **−28** |
| IAM failures | 18 | 15 | **−3** |

Four targeted fixes resolved **75% of all critical findings** and **77% of all high findings**. This is the core argument for risk-based prioritization: a small number of well-chosen remediations delivers outsized security improvement.

---

## CIS AWS Foundations Benchmark Mapping

| Finding | CIS Control | Description | Status |
|---|---|---|---|
| Root MFA disabled | CIS 1.1 | Enable MFA for the root account | ✅ Remediated |
| AdministratorAccess on IAM user | CIS 1.16 | Ensure IAM policies are attached only to groups or roles | ✅ Remediated |
| CloudTrail not enabled | CIS 3.1 | Ensure CloudTrail is enabled in all regions | ✅ Remediated |
| S3 public access not blocked | CIS 2.1 | Ensure S3 Block Public Access is configured | ✅ Remediated |

---

## Scope & Limitations

This assessment was conducted on a standalone personal AWS account. Several Prowler findings were intentionally excluded from remediation scope — not because they were ignored, but because they are inapplicable or impractical in this environment:

- **AWS Organizations SCP controls** — Prowler flags the absence of Service Control Policies, which are only available when the account is part of an AWS Organization. A standalone account cannot implement these controls regardless of configuration effort.
- **Firewall Manager (FMS)** — Requires AWS Business or Enterprise Support subscription. Not available on a personal account.
- **Hardware MFA** — CIS recommends hardware MFA (YubiKey, etc.) for root accounts. A virtual MFA device was applied instead, which satisfies the spirit of the control for a personal account environment.
- **AccessAnalyzer, Bedrock guardrails, CloudWatch metric filters** — These represent legitimate production security controls but fall outside the identity, logging, and data exposure scope of this assessment.

The remaining 115 failures after remediation are almost entirely composed of these out-of-scope enterprise controls. The four in-scope findings — the ones with direct, exploitable attacker impact — were all resolved.

**What this assessment does not include:** SIEM integration, automated alerting pipelines, continuous compliance monitoring, or infrastructure-as-code remediation (Terraform). These represent natural next steps for a production environment.

---

## Key Takeaways

**1. Default AWS accounts are not secure by default.**  
A fresh account with minimal resources failed 58.75% of 573 security checks — including four CRITICAL findings. Security posture requires deliberate, proactive effort from day one.

**2. Volume of findings is not the right metric.**  
141 failures sounds alarming. But most were low-severity or enterprise-scale controls inapplicable to a standalone account. Four targeted fixes resolved the majority of genuine risk. Chasing every finding equally would have diluted focus and delivered less actual security improvement.

**3. Python automation changes the scale of security analysis.**  
240 raw CSV findings is unmanageable for manual review. A 50-line Python script reduced that to 10 actionable issues in seconds — the same logic that underlies automated triage in real SIEM and SOAR environments.

**4. Logging is a prerequisite for everything else.**  
Without CloudTrail, no other security control can be verified or investigated after the fact. Enabling audit logging was not just one of four fixes — it was the fix that makes all future security work meaningful.

**5. Pass rate increased while finding count increased — and that is correct.**  
Post-remediation, Prowler found more total findings (258 vs 240) because enabling CloudTrail expanded the detectable resource surface. This is a common source of confusion in CSPM assessments. The improvement metric is pass rate, not raw finding count.

---

## Author

**Shashank** · Cybersecurity Student · Cloud Security Enthusiast  
GitHub: [@Shashankk2601](https://github.com/Shashankk2601)

---

*This assessment was conducted on a personal AWS account in a controlled, isolated environment for educational and portfolio purposes. No production systems or third-party data were involved.*
