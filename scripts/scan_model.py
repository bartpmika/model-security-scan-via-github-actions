#!/usr/bin/env python3
"""
Prisma AIRS Model Security Scanner

Scans an AI model against Palo Alto Prisma AIRS security policies
before allowing deployment. Exits non-zero if the model fails the
security assessment, blocking the CI/CD pipeline.
"""

import argparse
import json
import os
import sys
import time

import requests
import yaml


def get_access_token(client_id, client_secret, tsg_id):
    """Authenticate to Prisma AIRS via OAuth2 client credentials flow."""
    auth_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    payload = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{tsg_id}",
    }
    response = requests.post(
        auth_url,
        data=payload,
        auth=(client_id, client_secret),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def submit_model_scan(api_endpoint, access_token, model_config):
    """Submit a model for security scanning via the AIRS Model Security API."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    hf_id = model_config["model"]["huggingface_id"]
    scan_payload = {
        "security_group_uuid": model_config["security"]["security_profile_id"],
        "model_uri": f"https://huggingface.co/{hf_id}",
        "scan_origin": "MODEL_SECURITY_SDK",
        "labels": [
            {"key": "deployment_target", "value": "vertex_ai"},
            {"key": "machine_type", "value": model_config["deployment"]["machine_type"]},
            {"key": "version", "value": model_config["model"].get("version", "unknown").replace(".", "-")},
            {"key": "pipeline", "value": "github-actions"},
        ],
    }

    print(f"  POST {api_endpoint}/data/v1/scans")
    print(f"  Payload: {json.dumps(scan_payload, indent=2)}")

    response = requests.post(
        f"{api_endpoint}/data/v1/scans",
        headers=headers,
        json=scan_payload,
        timeout=60,
    )
    if not response.ok:
        print(f"  ERROR: {response.status_code} {response.reason}")
        print(f"  Response: {response.text}")
        response.raise_for_status()
    return response.json()


def poll_scan_status(api_endpoint, access_token, scan_id, timeout_seconds=300):
    """Poll for scan completion if the scan is asynchronous."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        response = requests.get(
            f"{api_endpoint}/data/v1/scans/{scan_id}",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()

        status = result.get("status", "").lower()
        if status in ("completed", "passed", "failed", "blocked"):
            return result

        print(f"  Scan status: {status} ... waiting")
        time.sleep(10)

    print("ERROR: Scan timed out.")
    sys.exit(1)


def print_scan_results(scan_result, model_name):
    """Pretty-print the scan results for CI log visibility."""
    print()
    print("=" * 64)
    print("  PRISMA AIRS MODEL SECURITY SCAN RESULTS")
    print("=" * 64)
    print(f"  Model:        {model_name}")
    print(f"  Scan ID:      {scan_result.get('scan_id', scan_result.get('id', 'N/A'))}")
    print(f"  Status:       {scan_result.get('status', 'N/A')}")
    print(f"  Action:       {scan_result.get('action', 'N/A')}")
    print(f"  Risk Score:   {scan_result.get('risk_score', 'N/A')}")
    print(f"  Category:     {scan_result.get('category', 'N/A')}")

    # Print rule violations if present
    violations = scan_result.get("rule_violations", scan_result.get("findings", []))
    if violations:
        print(f"  Violations:   {len(violations)}")
        for v in violations:
            severity = v.get("severity", v.get("level", "unknown"))
            desc = v.get("description", v.get("rule_name", "No description"))
            print(f"    [{str(severity).upper()}] {desc}")

    # Print full response for debugging in CI
    print()
    print("  Full API Response:")
    print(f"  {json.dumps(scan_result, indent=2)}")

    print("=" * 64)
    print()


def evaluate_results(scan_result):
    """Evaluate scan results. Returns True if the model is allowed."""
    status = scan_result.get("status", "").lower()
    action = scan_result.get("action", "").lower()
    risk_score = scan_result.get("risk_score", 0)

    # Check for explicit block/fail signals
    if action == "block" or status in ("failed", "blocked"):
        print("FAILED: Model blocked by Prisma AIRS security policy.")
        print("The model will NOT be deployed.")
        return False

    if risk_score and int(risk_score) >= 80:
        print(f"FAILED: Risk score {risk_score} exceeds threshold (80).")
        print("The model will NOT be deployed.")
        return False

    # Check for rule violations
    violations = scan_result.get("rule_violations", scan_result.get("findings", []))
    critical_violations = [
        v for v in violations
        if str(v.get("severity", v.get("level", ""))).lower() in ("critical", "high")
    ]
    if critical_violations:
        print(f"FAILED: {len(critical_violations)} critical/high severity violations found.")
        print("The model will NOT be deployed.")
        return False

    print("PASSED: Model approved by Prisma AIRS security policy.")
    print("The model is cleared for deployment.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Scan an AI model with Prisma AIRS Model Security"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the model configuration YAML file",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    if not config.get("security", {}).get("scan_enabled", True):
        print("Security scan is disabled in model config. Skipping.")
        sys.exit(0)

    client_id = os.environ.get("MODEL_SECURITY_CLIENT_ID")
    client_secret = os.environ.get("MODEL_SECURITY_CLIENT_SECRET")
    tsg_id = os.environ.get("TSG_ID")
    api_endpoint = os.environ.get(
        "MODEL_SECURITY_API_ENDPOINT",
        "https://api.sase.paloaltonetworks.com/aims",
    )

    if not all([client_id, client_secret, tsg_id]):
        print("ERROR: Missing required environment variables.")
        print("Set MODEL_SECURITY_CLIENT_ID, MODEL_SECURITY_CLIENT_SECRET, and TSG_ID.")
        sys.exit(1)

    model_name = config["model"]["huggingface_id"]

    print(f"Authenticating with Prisma AIRS (TSG: {tsg_id})...")
    token = get_access_token(client_id, client_secret, tsg_id)
    print("Authentication successful.")

    print(f"Submitting model for security scan: {model_name}")
    result = submit_model_scan(api_endpoint, token, config)

    # If the API returns a scan_id for async processing, poll for results
    if result.get("scan_id") and result.get("status", "").lower() not in (
        "completed",
        "passed",
        "failed",
        "blocked",
    ):
        print(f"Scan submitted (ID: {result['scan_id']}). Polling for results...")
        result = poll_scan_status(api_endpoint, token, result["scan_id"])

    print_scan_results(result, model_name)

    if not evaluate_results(result):
        sys.exit(1)


if __name__ == "__main__":
    main()
