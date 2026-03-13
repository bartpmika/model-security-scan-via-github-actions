#!/usr/bin/env python3
"""
Test a deployed Vertex AI model endpoint.

Discovers the endpoint by display name, sends a test prompt,
and prints the model response. Can be used in CI/CD or locally.
"""

import argparse
import json
import os
import subprocess
import sys

import yaml


def find_endpoint(project_id, region, display_name):
    """Find the endpoint ID for a deployed model by display name."""
    result = subprocess.run(
        [
            "gcloud", "ai", "endpoints", "list",
            "--project", project_id,
            "--region", region,
            "--format", "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    endpoints = json.loads(result.stdout)
    for ep in endpoints:
        if display_name in ep.get("displayName", ""):
            endpoint_id = ep["name"].split("/")[-1]
            return endpoint_id
    return None


def send_prediction(project_id, region, endpoint_id, prompt):
    """Send a prediction request to the Vertex AI endpoint."""
    request_payload = {
        "instances": [
            {
                "inputs": prompt,
                "parameters": {
                    "max_tokens": 256,
                    "temperature": 0.7,
                },
            }
        ]
    }

    # Write request to a temp file for gcloud
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(request_payload, f)
        request_file = f.name

    try:
        result = subprocess.run(
            [
                "gcloud", "ai", "endpoints", "predict", endpoint_id,
                "--project", project_id,
                "--region", region,
                "--json-request", request_file,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    finally:
        os.unlink(request_file)


def main():
    parser = argparse.ArgumentParser(
        description="Test a deployed Vertex AI model endpoint"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the model configuration YAML file",
    )
    parser.add_argument(
        "--prompt",
        default="Explain what AI model security scanning is in one sentence.",
        help="Test prompt to send to the model",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    project_id = os.environ.get("GCP_PROJECT_ID")
    region = os.environ.get("GCP_REGION", config["deployment"].get("region", "us-central1"))

    if not project_id:
        print("ERROR: GCP_PROJECT_ID environment variable is required.")
        sys.exit(1)

    display_name = config["model"]["display_name"] + "-secure"

    print(f"Looking for endpoint: {display_name}")
    print(f"  Project: {project_id}")
    print(f"  Region:  {region}")
    print()

    endpoint_id = find_endpoint(project_id, region, display_name)

    if not endpoint_id:
        print(f"ERROR: No endpoint found matching '{display_name}'")
        print("Make sure the model has been deployed first.")
        sys.exit(1)

    print(f"Found endpoint: {endpoint_id}")
    print(f"Sending test prompt: \"{args.prompt}\"")
    print()

    response = send_prediction(project_id, region, endpoint_id, args.prompt)

    print("=" * 64)
    print("  MODEL RESPONSE")
    print("=" * 64)
    print(json.dumps(response, indent=2))
    print("=" * 64)
    print()
    print("Endpoint test PASSED - model is responding.")


if __name__ == "__main__":
    main()
