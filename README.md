# AWS Security Posture Assessment (Prowler)

## Overview

Performed a cloud security audit on an intentionally misconfigured AWS account using Prowler.
Identified and remediated critical misconfigurations to improve security posture.

## Results

* Pass rate improved from **39.58% → 54.26%**
* Critical issues reduced from **4 → 1**
* High severity issues reduced from **22 → 5**

## Key Issues Fixed

* Root MFA disabled → Enabled MFA
* CloudTrail disabled → Enabled logging
* AWS Config disabled → Enabled monitoring

## Tools Used

* AWS (IAM, S3, CloudTrail, Config)
* Prowler
* Python (pandas)
  
## Analysis & Reports

- High/Critical Findings → `reports/high_critical_findings.csv`
- Baseline Report → `reports/baseline_report.txt`
- Remediation Report → `reports/remediation_report.txt`

## Key Impact

- Reduced critical issues by **75% (4 → 1)**
- Reduced high severity issues by **77% (22 → 5)**
- Improved pass rate from **39.58% → 54.26%**
  
## Project Structure

* baseline-scan/
* remediation-scan/
* screenshots/
* script/
* reports/
  
