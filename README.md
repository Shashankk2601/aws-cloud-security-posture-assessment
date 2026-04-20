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

## Project Structure

* baseline-scan/
* remediation-scan/
* screenshots/
* script/
