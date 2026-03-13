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

        outcome = result.get("eval_outcome", "").upper()
        if outcome in ("PASS", "PASSED", "FAIL", "FAILED", "BLOCKED", "ALLOWED", "COMPLETED"):
            return result

        elapsed = int(time.time() - start_time)
        print(f"  Scan status: {outcome} ({elapsed}s elapsed) ... waiting")
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
    print(f"  Scan UUID:    {scan_result.get('uuid', 'N/A')}")
    print(f"  Outcome:      {scan_result.get('eval_outcome', 'N/A')}")
    print(f"  Summary:      {scan_result.get('eval_summary', 'N/A')}")
    print(f"  Sec. Group:   {scan_result.get('security_group_name', 'N/A')}")
    print(f"  Rules:        {scan_result.get('enabled_rule_count_snapshot', 'N/A')}")
    print(f"  Files Scanned:{scan_result.get('total_files_scanned', 'N/A')}")
    print(f"  Files Skipped:{scan_result.get('total_files_skipped', 'N/A')}")

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
    outcome = scan_result.get("eval_outcome", "").upper()
    error_code = scan_result.get("error_code")
    error_message = scan_result.get("error_message")

    if error_code:
        print(f"FAILED: Scan error - {error_code}: {error_message}")
        print("The model will NOT be deployed.")
        return False

    if outcome in ("FAIL", "FAILED", "BLOCKED"):
        summary = scan_result.get("eval_summary", "No details provided")
        print(f"FAILED: Model blocked by Prisma AIRS security policy.")
        print(f"  Summary: {summary}")
        print("The model will NOT be deployed.")
        return False

    if outcome in ("PASS", "PASSED", "ALLOWED"):
        print("PASSED: Model approved by Prisma AIRS security policy.")
        print("The model is cleared for deployment.")
        return True

    # For unknown outcomes after polling, fail safe
    print(f"WARNING: Unexpected scan outcome '{outcome}'. Blocking deployment.")
    print("The model will NOT be deployed.")
    return False


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

    # The API returns a UUID and eval_outcome. Poll until scan completes.
    scan_uuid = result.get("uuid")
    outcome = result.get("eval_outcome", "").upper()
    terminal_states = ("PASS", "PASSED", "FAIL", "FAILED", "BLOCKED", "ALLOWED", "COMPLETED")
    if scan_uuid and outcome not in terminal_states:
        print(f"Scan submitted (UUID: {scan_uuid}). Polling for results...")
        result = poll_scan_status(api_endpoint, token, scan_uuid)

    print_scan_results(result, model_name)

    if not evaluate_results(result):
        sys.exit(1)


if __name__ == "__main__":
    main()
