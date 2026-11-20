#!/usr/bin/env python3
"""
InfraFlow G07.4 — External GCP Consumer Negative Security Integration Suite.
Validates that invalid, malicious, bypass, or unauthorized GCP configurations are strictly rejected.

Scenarios Tested (22 vectors):
 1. Invalid GCP project ID
 2. Invalid GCP region
 3. Invalid Service Account email
 4. Invalid WIF provider resource
 5. Wrong GCS bucket name
 6. Unsafe backend prefix
 7. Attempted directory traversal
 8. Symlink workspace escape
 9. Mutable reusable workflow reference
10. Untrusted PR credential request (SEC-02)
11. Attempted GCP authentication enablement (fail-closed simulation invariant)
12. Attempted policy evaluation bypass (enable-policy-evaluation: false)
13. Attempted Trivy scanning bypass (enable-trivy: false)
14. Wildcard WIF audience
15. Incorrect GitHub OIDC issuer
16. Unrestricted repository access condition
17. Untrusted repository identity
18. Public GCS bucket access
19. Overprivileged storage IAM roles
20. Missing required policy evidence (missing attribute mapping)
21. Attempt to bypass security summary
22. Malformed or unsupported Terraform backend configuration (empty prefix)
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Discover platform directory (CI checkout in .infraflow-platform or local sibling)
if os.path.isdir(os.path.join(REPO_ROOT, ".infraflow-platform")):
    PLATFORM_DIR = os.path.join(REPO_ROOT, ".infraflow-platform")
elif os.path.isdir(os.path.abspath(os.path.join(REPO_ROOT, "..", "infraflow"))):
    PLATFORM_DIR = os.path.abspath(os.path.join(REPO_ROOT, "..", "infraflow"))
elif os.path.isdir("/home/tharuka/projects/infraflow"):
    PLATFORM_DIR = "/home/tharuka/projects/infraflow"
else:
    raise RuntimeError(f"Cannot locate platform repository from {REPO_ROOT}")

REUSABLE_GCP_WF = os.path.join(PLATFORM_DIR, ".github", "workflows", "reusable-tf-gcp.yml")
WIF_POLICY = os.path.join(PLATFORM_DIR, "policies", "gcp", "wif_oidc.rego")
STORAGE_POLICY = os.path.join(PLATFORM_DIR, "policies", "gcp", "storage_backend.rego")

if not os.path.isfile(REUSABLE_GCP_WF):
    raise RuntimeError(f"Reusable workflow not found at {REUSABLE_GCP_WF}")
if not os.path.isfile(WIF_POLICY):
    raise RuntimeError(f"WIF policy not found at {WIF_POLICY}")
if not os.path.isfile(STORAGE_POLICY):
    raise RuntimeError(f"Storage policy not found at {STORAGE_POLICY}")

# Extract workflow steps from reusable-tf-gcp.yml
with open(REUSABLE_GCP_WF, "r", encoding="utf-8") as f:
    wf_data = yaml.safe_load(f)

val_steps = {s["id"]: s["run"] for s in wf_data["jobs"]["validate-inputs"]["steps"] if "id" in s and "run" in s}
GUARD_SCRIPT = val_steps["guard"]

cf_steps = {s["id"]: s["run"] for s in wf_data["jobs"]["cloud-free-plan"]["steps"] if "id" in s and "run" in s}
VERIFY_WORKSPACE_SCRIPT = cf_steps.get("verify_workspace", "")

sum_steps = {s["id"]: s["run"] for s in wf_data["jobs"]["summary"]["steps"] if "id" in s and "run" in s}
SUMMARY_SCRIPT = sum_steps["aggregate"]


def get_conftest_bin():
    candidates = [
        shutil.which("conftest"),
        "/home/tharuka/.local/bin/conftest",
        os.path.expanduser("~/.local/bin/conftest"),
        "/usr/local/bin/conftest",
        "/usr/bin/conftest",
    ]
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        candidates.insert(0, os.path.join(runner_temp, "bin", "conftest"))
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise RuntimeError("conftest binary not found in environment")


def run_guard(env_overrides):
    base_env = {
        "INPUT_VERSION": "1.10.4",
        "INPUT_DIR": ".",
        "INPUT_VAR_FILE": "",
        "INPUT_ENV": "dev",
        "INPUT_PROJECT_ID": "infraflow-ref-project",
        "INPUT_GCP_REGION": "us-central1",
        "INPUT_WIF_PROVIDER": "projects/123456789012/locations/global/workloadIdentityPools/infraflow-pool/providers/github-provider",
        "INPUT_SERVICE_ACCOUNT": "infraflow-sa@infraflow-ref-project.iam.gserviceaccount.com",
        "INPUT_BUCKET": "infraflow-tfstate-bucket",
        "INPUT_PREFIX": "terraform/state/dev",
        "INPUT_SEVERITY": "HIGH,CRITICAL",
        "ENABLE_GCP_AUTH": "false",
        "ENABLE_POLICY_EVAL": "true",
        "ENABLE_TRIVY": "true",
        "INPUT_POLICY_DIR": "policies",
        "EVENT_NAME": "push",
        "TARGET_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "TM-threemavithana/infraflow-consumer-test",
        "WORKFLOW_REPO": "TM-threemavithana/infraflow",
        "WORKFLOW_SHA": "543e426b4d9530daf999394710b3ba6262534f16",
        "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@543e426b4d9530daf999394710b3ba6262534f16",
    }
    base_env.update(env_overrides)
    env = {k: str(v) for k, v in base_env.items()}
    res = subprocess.run(
        ["bash", "-c", GUARD_SCRIPT],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return res.returncode, res.stdout + res.stderr


def run_conftest_eval(policy_path, namespace, input_dict):
    conftest_bin = get_conftest_bin()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(input_dict, f)
        tmp_path = f.name

    try:
        cmd = [conftest_bin, "test", "--namespace", namespace, "--policy", policy_path, "--no-color", tmp_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode, res.stdout + res.stderr
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


total_tests = 0
passed_tests = 0
failed_tests = []


def record_result(name, is_rejected, output, expected_snippet):
    global total_tests, passed_tests, failed_tests
    total_tests += 1
    snippet_matched = expected_snippet.lower() in output.lower()
    if is_rejected and snippet_matched:
        passed_tests += 1
        print(f"  [ PASS ] {name} (Rejected as expected: '{expected_snippet}')")
    else:
        failed_tests.append((name, output))
        print(f"  [ FAIL ] {name}")
        print(f"          Expected Snippet: '{expected_snippet}'")
        print(f"          Output Preview: {output[:300]}")


print("==============================================================================")
print(">>> InfraFlow G07.4 External GCP Consumer Negative Security Integration Suite")
print("==============================================================================")

# Scenario 1: Invalid GCP Project ID
rc, out = run_guard({"INPUT_PROJECT_ID": "bad_proj_with_underscore"})
record_result("Scenario 01: Invalid GCP Project ID Rejected", rc != 0, out, "project-id")

# Scenario 2: Invalid GCP Region
rc, out = run_guard({"INPUT_GCP_REGION": "us_central1"})
record_result("Scenario 02: Invalid GCP Region Rejected", rc != 0, out, "region")

# Scenario 3: Invalid Service Account Email
rc, out = run_guard({"INPUT_SERVICE_ACCOUNT": "admin@gmail.com"})
record_result("Scenario 03: Invalid Service Account Email Rejected", rc != 0, out, "Service Account")

# Scenario 4: Invalid WIF Provider Resource
rc, out = run_guard({"INPUT_WIF_PROVIDER": "invalid-provider-resource"})
record_result("Scenario 04: Invalid WIF Provider Resource Rejected", rc != 0, out, "Workload Identity Provider")

# Scenario 5: Wrong GCS Bucket Name (reserved goog/google prefix)
rc, out = run_guard({"INPUT_BUCKET": "google-state-storage"})
record_result("Scenario 05: Reserved GCS Bucket Prefix Rejected", rc != 0, out, "goog")

# Scenario 6: Unsafe Backend Prefix
rc, out = run_guard({"INPUT_PREFIX": "state/../../escape"})
record_result("Scenario 06: Backend Prefix Path Traversal Rejected", rc != 0, out, "backend-prefix")

# Scenario 7: Attempted Directory Traversal
rc, out = run_guard({"INPUT_DIR": "../../etc"})
record_result("Scenario 07: Working Directory Path Traversal Rejected", rc != 0, out, "Path traversal")

# Scenario 8: Symlink Workspace Escape
with tempfile.TemporaryDirectory() as temp_dir:
    ws_dir = os.path.join(temp_dir, "workspace")
    outside_dir = os.path.join(temp_dir, "outside")
    os.makedirs(ws_dir)
    os.makedirs(outside_dir)
    symlink_target = os.path.join(ws_dir, "evil_symlink")
    os.symlink(outside_dir, symlink_target)
    env = {
        "GITHUB_WORKSPACE": ws_dir,
        "INPUT_DIR": "evil_symlink",
        "INPUT_VAR_FILE": "",
        "POLICY_DIR": "",
    }
    res = subprocess.run(["bash", "-c", VERIFY_WORKSPACE_SCRIPT], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    record_result("Scenario 08: Symlink Workspace Escape Rejected", res.returncode != 0, res.stdout + res.stderr, "symbolic link")

# Scenario 9: Mutable Reusable Workflow Reference
rc, out = run_guard({"WORKFLOW_SHA": "main", "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@main"})
record_result("Scenario 09: Mutable Workflow Reference Rejected", rc != 0, out, "immutable 40-character hexadecimal commit SHA")

# Scenario 10: Untrusted PR Credential Request (SEC-02)
rc, out = run_guard({"EVENT_NAME": "pull_request", "ENABLE_GCP_AUTH": "true"})
record_result("Scenario 10: Untrusted PR Cloud Auth Request Rejected (SEC-02)", rc != 0, out, "disabled")

# Scenario 11: Attempted GCP Authentication Enablement
rc, out = run_guard({"ENABLE_GCP_AUTH": "true"})
record_result("Scenario 11: Live GCP Authentication Strictly Rejected (G07 Invariant)", rc != 0, out, "strictly disabled in Milestone G07.2")

# Scenario 12: Attempted Policy Evaluation Bypass
rc, out = run_guard({"ENABLE_POLICY_EVAL": "false"})
record_result("Scenario 12: Disabling Policy Evaluation Rejected", rc != 0, out, "Disabling mandatory policy evaluation")

# Scenario 13: Attempted Trivy Scanning Bypass
rc, out = run_guard({"ENABLE_TRIVY": "false"})
record_result("Scenario 13: Disabling Trivy Scanning Rejected", rc != 0, out, "Disabling mandatory Trivy IaC scanning")

# Scenario 14: Wildcard WIF Audience
payload_wif_aud = {
    "resource": {
        "google_iam_workload_identity_pool_provider": {
            "bad_prov": [{
                "oidc": [{
                    "issuer_uri": "https://token.actions.githubusercontent.com",
                    "allowed_audiences": ["*"]
                }],
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.repository": "assertion.repository"
                },
                "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow-consumer-test' && assertion.ref == 'refs/heads/main'"
            }]
        }
    }
}
rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_wif_aud)
record_result("Scenario 14: Wildcard WIF Audience Rejected", rc != 0, out, "wildcard '*' audience")

# Scenario 15: Incorrect GitHub OIDC Issuer
payload_wif_issuer = {
    "resource": {
        "google_iam_workload_identity_pool_provider": {
            "bad_issuer": [{
                "oidc": [{
                    "issuer_uri": "https://attacker-issuer.com"
                }],
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.repository": "assertion.repository"
                },
                "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow-consumer-test' && assertion.ref == 'refs/heads/main'"
            }]
        }
    }
}
rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_wif_issuer)
record_result("Scenario 15: Untrusted OIDC Issuer Rejected", rc != 0, out, "must strictly be 'https://token.actions.githubusercontent.com'")

# Scenario 16: Unrestricted Repository Access Condition
payload_wif_unrestricted = {
    "resource": {
        "google_iam_workload_identity_pool_provider": {
            "bad_cond": [{
                "oidc": [{
                    "issuer_uri": "https://token.actions.githubusercontent.com"
                }],
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.repository": "assertion.repository"
                },
                "attribute_condition": ""
            }]
        }
    }
}
rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_wif_unrestricted)
record_result("Scenario 16: Unrestricted WIF Condition Rejected", rc != 0, out, "missing mandatory 'attribute_condition'")

# Scenario 17: Untrusted Repository Identity
payload_wif_bad_repo = {
    "resource": {
        "google_iam_workload_identity_pool_provider": {
            "sub_prov": [{
                "oidc": [{
                    "issuer_uri": "https://token.actions.githubusercontent.com"
                }],
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.repository": "assertion.repository"
                },
                "attribute_condition": "assertion.actor == 'malicious-actor'"
            }]
        }
    }
}
rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_wif_bad_repo)
record_result("Scenario 17: Repository Identity Substitution Rejected", rc != 0, out, "must explicitly filter on 'assertion.repository'")

# Scenario 18: Public GCS Bucket Access
payload_storage_public_acl = {
    "resource": {
        "google_storage_bucket_access_control": {
            "public_acl": [{
                "bucket": "infraflow-state",
                "entity": "allUsers",
                "role": "READER"
            }]
        }
    }
}
rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload_storage_public_acl)
record_result("Scenario 18: Public GCS Bucket ACL Rejected", rc != 0, out, "grants public access to 'allUsers'")

# Scenario 19: Overprivileged Storage IAM Roles
payload_storage_owner = {
    "resource": {
        "google_storage_bucket_iam_binding": {
            "owner_iam": [{
                "bucket": "infraflow-state",
                "role": "roles/owner",
                "members": ["serviceAccount:deployer@proj.iam.gserviceaccount.com"]
            }]
        }
    }
}
rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload_storage_owner)
record_result("Scenario 19: Overprivileged Primitive Storage Role Rejected", rc != 0, out, "overprivileged primitive role")

# Scenario 20: Missing Required Policy Evidence (Missing attribute mapping)
payload_missing_mapping = {
    "resource": {
        "google_iam_workload_identity_pool_provider": {
            "bad_mapping": [{
                "oidc": [{
                    "issuer_uri": "https://token.actions.githubusercontent.com"
                }],
                "attribute_mapping": {
                    "google.subject": "assertion.sub"
                    # missing attribute.repository
                },
                "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow-consumer-test' && assertion.ref == 'refs/heads/main'"
            }]
        }
    }
}
rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_missing_mapping)
record_result("Scenario 20: Missing Mandatory Attribute Mapping Rejected", rc != 0, out, "attribute_mapping must map 'attribute.repository'")

# Scenario 21: Attempt to Bypass Security Summary
with tempfile.NamedTemporaryFile("w", delete=False) as out_f:
    out_path = out_f.name
try:
    env = dict(os.environ)
    env["GITHUB_OUTPUT"] = out_path
    env["VALIDATE_RESULT"] = "failure"
    env["CF_PLAN_RESULT"] = "success"
    env["ENABLE_GCP_AUTH"] = "false"
    res = subprocess.run(["bash", "-c", SUMMARY_SCRIPT], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    summary_outputs = {}
    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                summary_outputs[k] = v
    is_rejected = (res.returncode != 0) and (summary_outputs.get("authorization-status") == "rejected")
    record_result("Scenario 21: Summary Aggregator Failure Propagation Verified", is_rejected, f"auth={summary_outputs.get('authorization-status')}", "auth=rejected")
finally:
    if os.path.exists(out_path):
        os.unlink(out_path)

# Scenario 22: Malformed or Unsupported Terraform Backend Configuration (Empty prefix)
payload_empty_prefix = {
    "terraform": [{
        "backend": [{
            "gcs": [{
                "bucket": "infraflow-tfstate",
                "prefix": ""
            }]
        }]
    }]
}
rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload_empty_prefix)
record_result("Scenario 22: Empty GCS Backend Prefix Rejected", rc != 0, out, "prefix must not be empty")

print("==============================================================================")
print(f"Summary: {passed_tests}/{total_tests} scenarios rejected as expected.")
print("==============================================================================")

if failed_tests:
    print(f"FAILED: {len(failed_tests)} scenarios did not fail as expected.")
    sys.exit(1)

print("All 22 negative security scenarios passed successfully (fail-closed verified).")
sys.exit(0)
