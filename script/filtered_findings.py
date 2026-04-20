"""
Prowler Security Findings Analyzer
AWS Security Posture Assessment Project

Author: Shashank
Description:
Processes Prowler CSV output to identify high-risk findings,
summarize security posture, and generate a structured report.
"""

import pandas as pd
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────
INPUT_FILE  = "prowler-output-112920804082-20260404185738.csv"
OUTPUT_FILE = "high_priority_findings.csv"
REPORT_FILE = "security_summary_report.txt"
ACCOUNT_ID  = "112920804082"
# ────────────────────────────────────────────────────────


def load(path):
    """Load CSV safely"""
    try:
        df = pd.read_csv(path, sep=";")
        return df
    except FileNotFoundError:
        print(f"❌ Error: File not found → {path}")
        exit()
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        exit()


def normalize(df):
    """Normalize column values for consistency"""
    df["SEVERITY"] = df["SEVERITY"].str.lower()
    df["STATUS"] = df["STATUS"].str.upper()
    return df


def summarize(df):
    """Generate summary statistics"""
    total = len(df)
    status = df["STATUS"].value_counts().to_dict()
    sev_fails = df[df["STATUS"] == "FAIL"]["SEVERITY"].value_counts().to_dict()
    return total, status, sev_fails


def priority_findings(df):
    """Filter high-priority failed findings"""
    pf = df[
        (df["STATUS"] == "FAIL") &
        (df["SEVERITY"].isin(["critical", "high"]))
    ].drop_duplicates(subset="CHECK_ID")

    return pf[
        [
            "CHECK_ID",
            "CHECK_TITLE",
            "SERVICE_NAME",
            "SEVERITY",
            "STATUS_EXTENDED",
            "REGION",
            "REMEDIATION_RECOMMENDATION_TEXT"
        ]
    ].copy()


def service_breakdown(df):
    """Count failures by AWS service"""
    return df[df["STATUS"] == "FAIL"]["SERVICE_NAME"].value_counts()


def generate_report(df, total, status, sev_fails):
    """Create human-readable report"""
    fails = status.get("FAIL", 0)
    passes = status.get("PASS", 0)

    fail_pct = round((fails / total) * 100, 2) if total else 0
    pass_pct = round((passes / total) * 100, 2) if total else 0

    lines = [
        "=" * 60,
        " AWS SECURITY POSTURE ASSESSMENT — BASELINE REPORT",
        f" Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f" Account   : {ACCOUNT_ID}",
        " Tool      : Prowler",
        "=" * 60,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f" Total checks : {total}",
        f" PASS         : {passes} ({pass_pct}%)",
        f" FAIL         : {fails} ({fail_pct}%)",
        f" MANUAL       : {status.get('MANUAL', 0)}",
        "",
        "SEVERITY BREAKDOWN (FAILURES ONLY)",
        "-" * 40,
    ]

    for sev in ["critical", "high", "medium", "low"]:
        lines.append(f" {sev.capitalize():<12}: {sev_fails.get(sev, 0)}")

    lines += ["", "FAILURES BY SERVICE", "-" * 40]

    for svc, cnt in service_breakdown(df).items():
        lines.append(f" {svc:<25}: {cnt}")

    lines += ["", "HIGH PRIORITY FINDINGS (Critical + High)", "-" * 40]

    priority = priority_findings(df)

    for _, row in priority.iterrows():
        lines += [
            f" [{row['SEVERITY'].upper()}] {row['CHECK_ID']}",
            f" Title  : {row['CHECK_TITLE']}",
            f" Detail : {row['STATUS_EXTENDED']}",
            ""
        ]

    lines += [
        "REMEDIATION APPROACH",
        "-" * 40,
        " Focus on high-impact security issues first (Critical/High).",
        " Apply least privilege, enable logging, and enforce MFA.",
        " Validate fixes with a follow-up security scan.",
        "",
        "=" * 60,
        " END OF REPORT",
        "=" * 60,
    ]

    text = "\n".join(lines)

    with open(REPORT_FILE, "w") as f:
        f.write(text)

    return text


def main():
    print(f"\n📂 Loading file: {INPUT_FILE}")

    df = load(INPUT_FILE)
    df = normalize(df)

    total, status, sev_fails = summarize(df)

    # Export filtered findings
    pf = priority_findings(df)
    pf.to_csv(OUTPUT_FILE, index=False)

    print(f"✅ Exported {len(pf)} high/critical findings → {OUTPUT_FILE}")

    # Generate report
    report = generate_report(df, total, status, sev_fails)

    print(f"📝 Report saved → {REPORT_FILE}\n")
    print(report)


if __name__ == "__main__":
    main()