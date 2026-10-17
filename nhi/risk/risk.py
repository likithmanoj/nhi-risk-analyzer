import argparse
from nhi.services.inventory import create_inventory
from nhi.risk.runners import (
    run_aws_checks,
    run_azure_checks,
    run_gcp_checks,
)
from nhi.remediation.dispatch import dispatch_remediation
from datetime import datetime, timezone
from nhi.aws.s3 import fetch_latest_scan, persist_scan_artifact
from nhi.remediation.diff import diff_findings
from nhi.services.export import export_findings_to_csv
from nhi.services.sarif import export_findings_to_sarif


def analyze_inventory(clouds=None):
    response = create_inventory(clouds=clouds)
    findings = []
    scanned = response.get("metadata", {}).get("scanned_providers", [])

    if "aws" in scanned and "aws" in response:
        findings.extend(run_aws_checks(response["aws"]))
    elif "users" in response:
        findings.extend(run_aws_checks(response))

    if "azure" in scanned and "azure" in response:
        findings.extend(run_azure_checks(response["azure"]))

    if "gcp" in scanned and "gcp" in response:
        findings.extend(run_gcp_checks(response["gcp"]))

    return findings

def main():
    parser = argparse.ArgumentParser(
        description="NHI Risk Analyzer & Remediation Engine for Multi-Cloud (AWS, Azure, GCP)"
    )

    parser.add_argument(
        "--cloud",
        choices=["aws", "azure", "gcp", "all"],
        default="all",
        help="Target cloud provider to scan (default: all configured)",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate remediation actions without making changes in AWS",
    )
    group.add_argument(
        "--remediate",
        action="store_true",
        help="Execute live remediation against detected findings",
    )
    parser.add_argument(
        "--csv",
        type=str,
        metavar="FILEPATH",
        help="Export detected findings to a CSV file at the specified path",
    )
    parser.add_argument(
        "--sarif",
        type=str,
        metavar="FILEPATH",
        help="Export detected findings to SARIF",
    )

    args = parser.parse_args()

    clouds = [args.cloud] if args.cloud != "all" else None
    print("[*] Running inventory and risk evaluation...")
    all_findings = analyze_inventory(clouds=clouds)
    print(f"[*] Total current findings detected: {len(all_findings)}")

    if args.csv:
        export_findings_to_csv(all_findings, args.csv)
    
    if args.sarif:
        export_findings_to_sarif(all_findings, args.sarif)


    print("[*] Fetching previous scan artifact from S3 for run-over-run diffing...")
    previous_scan = fetch_latest_scan()
    previous_findings = previous_scan.get("findings", []) if previous_scan else []

    diff_result = diff_findings(previous_findings, all_findings)
    summary = diff_result["summary"]

    print(f"\n{'='*40}")
    print("           RUN-OVER-RUN DIFF            ")
    print(f"{'='*40}")
    print(f" [+] New Findings:        {summary['new_count']}")
    print(f" [-] Resolved Findings:   {summary['resolved_count']}")
    print(f" [=] Unresolved Findings: {summary['unresolved_count']}")
    print(f"{'='*40}\n")

    stats = None
    if args.remediate:
        print("[!] Executing LIVE remediation...")
        stats = dispatch_remediation(all_findings, dry_run=False)
        print("Live Remediation Stats:", stats)
    elif args.dry_run:
        print("[*] Executing DRY RUN simulation...")
        stats = dispatch_remediation(all_findings, dry_run=True)
        print("Dry Run Stats:", stats)
    else:
        print(
            "[*] Scan complete. (Pass --dry-run to simulate containment or --remediate to execute live)"
        )

    artifact = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "diff": diff_result,
        "findings": all_findings,
        "remediation_stats": stats,
    }
    print("[*] Persisting scan artifact to S3...")
    persist_scan_artifact(artifact)


if __name__ == "__main__":
    main()