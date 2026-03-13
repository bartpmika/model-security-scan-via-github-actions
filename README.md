# Palo Alto Networks Prisma AIRS - Model Security in CI/CD

<p align="center">
  <img src="https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/primary-company-logo/PANW_Parent_Brand_Primary_Logo_Color_RGB.png" alt="Palo Alto Networks" width="400"/>
</p>

<p align="center">
  <strong>Shift-left AI model security. Scan models before they reach production.</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#testing-the-deployed-model">Testing</a> &bull;
  <a href="#configuration-reference">Configuration</a>
</p>

---

## Overview

This repository demonstrates how to integrate **Palo Alto Networks Prisma AIRS Model Security** scanning into a CI/CD pipeline using **GitHub Actions**. When a model configuration changes, the pipeline automatically scans the model against AIRS security policies and **only deploys to Google Cloud Vertex AI if the model passes the security assessment**.

### What Gets Scanned

Prisma AIRS Model Security evaluates AI models for:

- **Model provenance and supply chain risks** - Verifying the model source and integrity
- **Known vulnerabilities** - Checking against known CVEs and security advisories
- **Malicious payloads** - Detecting embedded malicious code or backdoors
- **Compliance violations** - Ensuring models meet organizational security policies
- **Training data risks** - Identifying potential data poisoning indicators

### Architecture

| Component | Technology |
|-----------|------------|
| **AI Model** | Google Gemma 3 1B (via Vertex AI Model Garden + HuggingFace) |
| **Model Hosting** | Google Cloud Vertex AI Endpoint |
| **Security Gate** | Palo Alto Networks Prisma AIRS Model Security |
| **CI/CD** | GitHub Actions |
| **Trigger** | Changes to `config/model-config.yaml` |

---

## How It Works

```
  Developer changes config/model-config.yaml
  (e.g., updates the model ID or version)
                    |
                    v
        GitHub Actions Triggered
        (push to main or pull request)
                    |
                    v
       +----------------------------+
       | Prisma AIRS Model Security |
       |       Scan                 |
       +----------------------------+
                    |
              +-----+-----+
              |           |
           PASSED      BLOCKED
              |           |
              v           v
      +-------------+   Pipeline fails.
      | Deploy to   |   Model is NOT
      | Vertex AI   |   deployed.
      | Endpoint    |   Developer is
      +-------------+   notified.
              |
              v
      +-------------+
      | Validate    |
      | Endpoint    |
      +-------------+
```

**On Pull Requests:** The security scan runs and reports pass/fail status, but the model is not deployed. This allows developers to verify model compliance before merging.

**On Push to Main:** If the security scan passes, the model is automatically deployed to a Vertex AI endpoint and validated.

---

## Quick Start

### Prerequisites

- A Google Cloud project with the [Vertex AI API](https://console.cloud.google.com/apis/library/aiplatform.googleapis.com) enabled
- A GCP service account with Vertex AI permissions (JSON key)
- A Palo Alto Networks Prisma AIRS subscription with API credentials
- A GitHub repository with Actions enabled

### 1. Fork This Repository

Fork this repository to your GitHub account.

### 2. Configure GitHub Secrets

Go to **Settings > Secrets and variables > Actions** in your forked repository and add the following secrets:

| Secret | Description | How to Obtain |
|--------|-------------|---------------|
| `GCP_PROJECT_ID` | Your Google Cloud project ID | Find it in the [GCP Console dashboard](https://console.cloud.google.com/home/dashboard) or run `gcloud config get-value project` |
| `GCP_REGION` | GCP region for deployment (e.g., `us-central1`) | Choose from [Vertex AI available regions](https://cloud.google.com/vertex-ai/docs/general/locations#available-regions). Use `us-central1` for the widest GPU availability. |
| `GCP_SA_KEY` | GCP service account JSON key (with Vertex AI Admin role) | Create a service account and download the key via [GCP IAM Console](https://console.cloud.google.com/iam-admin/serviceaccounts). Grant it the **Vertex AI Administrator** role. See [Creating service account keys](https://cloud.google.com/iam/docs/keys-create-delete). |
| `MODEL_SECURITY_CLIENT_ID` | Prisma AIRS OAuth client ID (service account) | Generate in the Prisma AIRS console under **Settings > Access Control > Service Accounts**. See [Prisma AIRS API Authentication](https://pan.dev/sase/docs/getstarted/). |
| `MODEL_SECURITY_CLIENT_SECRET` | Prisma AIRS OAuth client secret | Generated alongside the client ID when creating a service account in the Prisma AIRS console. |
| `TSG_ID` | Prisma AIRS Tenant Service Group ID | Found in the Prisma AIRS console under **Settings > Tenant Service Groups**, or embedded in the service account email (the numeric portion). See [TSG ID documentation](https://pan.dev/sase/docs/tenant-service-groups/). |
| `MODEL_SECURITY_API_ENDPOINT` | Prisma AIRS API endpoint URL | Use `https://api.sase.paloaltonetworks.com/aims` for US deployments. See [AIRS API reference](https://pan.dev/airs/) for regional endpoints. |

> **Tip:** You can also set secrets via the GitHub CLI:
> ```bash
> gh secret set GCP_PROJECT_ID --body "your-project-id"
> gh secret set GCP_SA_KEY < /path/to/service-account-key.json
> ```

### 3. Change the Model

Edit `config/model-config.yaml` to specify your desired model:

```yaml
model:
  huggingface_id: "google/gemma-3-1b-it"
  display_name: "gemma-3-1b-it"
  version: "1.0"
```

### 4. Push and Watch

Commit and push your changes. The pipeline will:

1. Detect the model configuration change
2. Run a Prisma AIRS security scan on the specified model
3. Deploy the model to Vertex AI (if the scan passes and on the `main` branch)
4. Validate the deployed endpoint

---

## Testing the Deployed Model

Once the model is deployed, you can test it locally using the provided test script.

### Using the Test Script

```bash
# Set your GCP credentials
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"

# Authenticate with GCP
gcloud auth login
gcloud config set project $GCP_PROJECT_ID

# Run the test script
python scripts/test_model.py \
  --config config/model-config.yaml \
  --prompt "What are the benefits of AI model security scanning?"
```

### Using gcloud Directly

```bash
# Find your endpoint ID
gcloud ai endpoints list --region=us-central1

# Send a prediction request
gcloud ai endpoints predict ENDPOINT_ID \
  --region=us-central1 \
  --json-request=request.json
```

Where `request.json` contains:

```json
{
  "instances": [
    {
      "inputs": "Explain model security in one sentence.",
      "parameters": {
        "max_tokens": 256,
        "temperature": 0.7
      }
    }
  ]
}
```

### Using curl with the REST API

```bash
# Get your access token
ACCESS_TOKEN=$(gcloud auth print-access-token)

# Find the endpoint
ENDPOINT_ID=$(gcloud ai endpoints list \
  --region=us-central1 \
  --filter="displayName~gemma-3-1b-it-secure" \
  --format="value(name)" | head -1)

# Send a request
curl -X POST \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://us-central1-aiplatform.googleapis.com/v1/${ENDPOINT_ID}:predict" \
  -d '{
    "instances": [
      {
        "inputs": "What is AI model security?",
        "parameters": {"max_tokens": 256, "temperature": 0.7}
      }
    ]
  }'
```

---

## Configuration Reference

### `config/model-config.yaml`

| Field | Description | Example |
|-------|-------------|---------|
| `model.huggingface_id` | HuggingFace model ID available in Vertex AI Model Garden | `google/gemma-3-1b-it` |
| `model.display_name` | Display name for the Vertex AI endpoint | `gemma-3-1b-it` |
| `model.description` | Human-readable model description | `Google Gemma 3 1B IT` |
| `model.version` | Version identifier for tracking changes | `1.0` |
| `deployment.machine_type` | GCP machine type for the endpoint | `g2-standard-12` |
| `deployment.accelerator_type` | GPU accelerator type | `NVIDIA_L4` |
| `deployment.accelerator_count` | Number of GPUs | `1` |
| `deployment.region` | GCP region | `us-central1` |
| `security.scan_enabled` | Enable/disable the security scan gate | `true` |
| `security.security_profile_id` | Prisma AIRS security profile UUID | UUID string |

### Swapping Models

To change the deployed model, edit the `model` section in `config/model-config.yaml`:

```yaml
# Example: Switch to Gemma 2 2B
model:
  huggingface_id: "google/gemma-2-2b-it"
  display_name: "gemma-2-2b-it"
  version: "2.0"
```

Commit and push - the pipeline will scan the new model before deploying.

---

## Cost Management

The default configuration deploys on a `g2-standard-12` machine with an `NVIDIA_L4` GPU. This incurs ongoing compute costs while the endpoint is active.

### Estimated Costs

| Resource | Approximate Cost |
|----------|-----------------|
| g2-standard-12 + NVIDIA L4 | ~$1.40/hour |

### Cleaning Up

To stop incurring costs, undeploy the model endpoint:

```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"

bash scripts/undeploy_model.sh
```

This script will find the deployed endpoint, undeploy all models, and delete the endpoint.

---

## Pipeline Details

### GitHub Actions Workflow

The workflow (`.github/workflows/model-security-scan.yml`) runs four jobs:

1. **Detect Changes** - Confirms `config/model-config.yaml` was modified
2. **Security Scan** - Authenticates with Prisma AIRS and scans the model. If the scan fails, the pipeline stops here.
3. **Deploy Model** - Deploys the scanned model to Vertex AI via Model Garden (main branch only)
4. **Test Model** - Sends a test prompt to verify the endpoint is responding

### Manual Trigger

The workflow can also be triggered manually via the **Actions** tab using the `workflow_dispatch` event.

---

## Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── model-security-scan.yml    # CI/CD pipeline definition
├── config/
│   └── model-config.yaml             # Model configuration (trigger file)
├── scripts/
│   ├── deploy_model.sh               # Vertex AI deployment script
│   ├── scan_model.py                 # Prisma AIRS security scan script
│   ├── test_model.py                 # Endpoint validation script
│   └── undeploy_model.sh             # Cleanup / cost control script
├── requirements.txt                   # Python dependencies
├── LICENSE
└── README.md
```

---

## Learn More

- [Prisma AIRS Model Security](https://docs.paloaltonetworks.com/ai-runtime-security)
- [Prisma AIRS API Documentation](https://pan.dev/airs/)
- [Google Vertex AI Model Garden](https://cloud.google.com/vertex-ai/generative-ai/docs/model-garden/use-models)
- [Vertex AI HuggingFace Integration](https://cloud.google.com/vertex-ai/generative-ai/docs/open-models/use-hugging-face-models)

---

<p align="center">
  <sub>Built with Palo Alto Networks Prisma AIRS &bull; Powered by Google Cloud Vertex AI</sub>
</p>
