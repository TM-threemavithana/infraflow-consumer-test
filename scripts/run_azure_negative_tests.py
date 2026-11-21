#!/usr/bin/env python3
"""
InfraFlow G07.7 — External Azure Consumer Negative Security Integration Suite.
Validates that invalid, malicious, bypass, or unauthorized Azure configurations
are strictly rejected by the reusable-tf-azure.yml guard and OPA policies.

Scenarios Tested (36 vectors):
 1. Live Azure auth strictly rejected (enable-azure-auth: true)
 2. SEC-02: Pull request with live auth strictly rejected
 3. Mandatory policy evaluation cannot be disabled
 4. Mandatory Trivy scanning cannot be disabled
 5. Untrusted platform repository rejected (wrong WORKFLOW_REPO)
 6. Mutable ref (branch name) rejected — must be 40-char SHA
 7. Invalid WORKFLOW_SHA (too short) rejected
 8. Empty WORKFLOW_SHA rejected
 9. Invalid Subscription ID (not a UUID) rejected
10. Subscription ID with uppercase GUID format (invalid format) rejected
11. Invalid Tenant ID (not a UUID) rejected
12. Invalid Client ID (not a UUID) rejected
13. Invalid Azure region (contains uppercase) rejected
14. Invalid Azure region (contains special characters) rejected
15. Invalid Resource Group name (ends with period) rejected
16. Invalid Resource Group name (exceeds 90 characters) rejected
17. Invalid Storage Account name (contains hyphens) rejected
18. Invalid Storage Account name (too long) rejected
19. Invalid Storage Account name (too short) rejected
20. Invalid Container name (starts with hyphen) rejected
21. Invalid Container name (consecutive hyphens) rejected
22. State blob key with path traversal (../) rejected
23. State blob key with leading slash rejected
24. Invalid Terraform version format rejected
25. Unsupported Terraform version below minimum (1.6.0) rejected
26. Absolute working directory path rejected
27. Working directory with path traversal rejected
28. Var-file with path traversal rejected
29. Var-file with absolute path rejected
30. Entra OIDC: wildcard audience rejected by OPA policy
31. Entra OIDC: wrong issuer rejected by OPA policy
32. Entra OIDC: missing repo context (repo substitution) rejected by OPA policy
33. Entra OIDC: tenant/client ID mismatch rejected by OPA policy
34. Storage backend: static key enabled rejected by OPA policy
35. Storage backend: public access allowed rejected by OPA policy
36. Storage backend: missing TLS enforcement rejected by OPA policy
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

REUSABLE_AZURE_WF = os.path.join(PLATFORM_DIR, ".github", "workflows", "reusable-tf-azure.yml")
ENTRA_OIDC_POLICY = os.path.join(PLATFORM_DIR, "policies", "azure", "entra_oidc.rego")
STORAGE_POLICY = os.path.join(PLATFORM_DIR, "policies", "azure", "storage_backend.rego")

if not os.path.isfile(REUSABLE_AZURE_WF):
    raise RuntimeError(f"Reusable workflow not found at {REUSABLE_AZURE_WF}")
if not os.path.isfile(ENTRA_OIDC_POLICY):
    raise RuntimeError(f"Entra OIDC policy not found at {ENTRA_OIDC_POLICY}")
if not os.path.isfile(STORAGE_POLICY):
    raise RuntimeError(f"Storage policy not found at {STORAGE_POLICY}")

# Extract guard script from reusable-tf-azure.yml
with open(REUSABLE_AZURE_WF, "r", encoding="utf-8") as f:
    wf_data = yaml.safe_load(f)

val_steps = {s["id"]: s["run"] for s in wf_data["jobs"]["validate-inputs"]["steps"] if "id" in s and "run" in s}
GUARD_SCRIPT = val_steps["guard"]


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
    """Run the Azure adapter guard script with given environment overrides."""
    base_env = {
        "INPUT_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000001",
        "INPUT_TENANT_ID": "00000000-0000-0000-0000-000000000002",
        "INPUT_CLIENT_ID": "00000000-0000-0000-0000-000000000003",
        "INPUT_AZURE_RG": "rg-infraflow-smoke",
        "INPUT_BACKEND_RG": "",
        "INPUT_REGION": "eastus",
        "INPUT_AZURE_SA": "stinfraflowsmoke01",
        "INPUT_BACKEND_SA": "",
        "INPUT_AZURE_CONTAINER": "tfstate",
        "INPUT_BACKEND_CONTAINER": "",
        "INPUT_AZURE_KEY": "smoke/terraform.tfstate",
        "INPUT_BACKEND_KEY": "",
        "INPUT_VERSION": "1.10.4",
        "INPUT_DIR": "test/g07-azure-adapter-smoke",
        "INPUT_VAR_FILE": "",
        "INPUT_ENV": "smoke",
        "ENABLE_AZURE_AUTH": "false",
        "ENABLE_POLICY_EVAL": "true",
        "INPUT_POLICY_DIR": "",
        "ENABLE_TRIVY": "true",
        "INPUT_SEVERITY": "HIGH,CRITICAL",
        "FAIL_DESTRUCTIVE": "false",
        "EVENT_NAME": "push",
        "TARGET_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "TM-threemavithana/infraflow-consumer-test",
        "WORKFLOW_REPO": "TM-threemavithana/infraflow",
        "WORKFLOW_SHA": "de8ff47dc513ea88892ef29b363e419d396b4290",
        "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@de8ff47dc513ea88892ef29b363e419d396b4290",
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
    """Evaluate an OPA/Conftest policy against a JSON input.

    Copies only the main policy file (not test files) to a temp directory to
    avoid conftest loading and running the unit test rules alongside deny rules.
    """
    conftest_bin = get_conftest_bin()

    # Write the input data to a temp JSON file
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(input_dict, f)
        tmp_path = f.name

    # Copy only the main policy (not *_test.rego) to an isolated temp dir
    policy_dir = tempfile.mkdtemp(prefix="infraflow_policy_")
    policy_copy = os.path.join(policy_dir, os.path.basename(policy_path))
    shutil.copy2(policy_path, policy_copy)

    try:
        cmd = [conftest_bin, "test", "--namespace", namespace, "--policy", policy_dir, "--no-color", tmp_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode, res.stdout + res.stderr
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        shutil.rmtree(policy_dir, ignore_errors=True)


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
        print(f"          Output Preview: {output[:400]}")


print("==============================================================================")
print(">>> InfraFlow G07.7 External Azure Consumer Negative Security Integration Suite")
print("==============================================================================")
print(f"Platform directory: {PLATFORM_DIR}")
print()

# =============================================================================
# SECTION A: AZURE AUTH & SECURITY GATE BYPASS VECTORS (1-4)
# =============================================================================
print("--- Section A: Security Gate Bypass Vectors ---")

# Vector 1: Live Azure authentication must be rejected
rc, out = run_guard({"ENABLE_AZURE_AUTH": "true"})
record_result("Vector 01: Live Azure auth (enable-azure-auth=true) rejected", rc != 0, out, "strictly disabled")

# Vector 2: SEC-02 — PR event requesting live auth must fail closed
rc, out = run_guard({"ENABLE_AZURE_AUTH": "true", "EVENT_NAME": "pull_request", "TARGET_REF": "refs/pull/5/merge"})
record_result("Vector 02: SEC-02 — PR event with live auth rejected", rc != 0, out, "strictly disabled")

# Vector 3: Mandatory policy evaluation cannot be disabled
rc, out = run_guard({"ENABLE_POLICY_EVAL": "false"})
record_result("Vector 03: Mandatory policy evaluation bypass rejected", rc != 0, out, "policy evaluation")

# Vector 4: Mandatory Trivy scanning cannot be disabled
rc, out = run_guard({"ENABLE_TRIVY": "false"})
record_result("Vector 04: Mandatory Trivy scan bypass rejected", rc != 0, out, "trivy")

# =============================================================================
# SECTION B: WORKFLOW TRUST BOUNDARY VECTORS (5-8)
# =============================================================================
print()
print("--- Section B: Workflow Trust Boundary Vectors ---")

# Vector 5: Untrusted platform repository
rc, out = run_guard({"WORKFLOW_REPO": "attacker-org/infraflow"})
record_result("Vector 05: Untrusted WORKFLOW_REPO rejected", rc != 0, out, "trusted repository")

# Vector 6: Mutable ref (branch name) — must be pinned SHA
rc, out = run_guard({"WORKFLOW_SHA": "refs/heads/main"})
record_result("Vector 06: Mutable branch reference rejected (not 40-char SHA)", rc != 0, out, "40-character")

# Vector 7: Short/invalid SHA
rc, out = run_guard({"WORKFLOW_SHA": "deadbeef"})
record_result("Vector 07: Short SHA (8 hex chars) rejected", rc != 0, out, "40-character")

# Vector 8: Empty WORKFLOW_SHA
rc, out = run_guard({"WORKFLOW_SHA": ""})
record_result("Vector 08: Empty WORKFLOW_SHA rejected", rc != 0, out, "40-character")

# =============================================================================
# SECTION C: AZURE IDENTITY INPUT VALIDATION (9-12)
# =============================================================================
print()
print("--- Section C: Azure Identity Input Validation ---")

# Vector 9: Invalid Subscription ID (not UUID)
rc, out = run_guard({"INPUT_SUBSCRIPTION_ID": "not-a-uuid"})
record_result("Vector 09: Non-UUID subscription-id rejected", rc != 0, out, "subscription-id")

# Vector 10: Invalid Subscription ID (UUID without hyphens)
rc, out = run_guard({"INPUT_SUBSCRIPTION_ID": "00000000000000000000000000000001"})
record_result("Vector 10: UUID without hyphens subscription-id rejected", rc != 0, out, "subscription-id")

# Vector 11: Invalid Tenant ID (not UUID)
rc, out = run_guard({"INPUT_TENANT_ID": "tenant-name-not-uuid"})
record_result("Vector 11: Non-UUID tenant-id rejected", rc != 0, out, "tenant-id")

# Vector 12: Invalid Client ID (not UUID)
rc, out = run_guard({"INPUT_CLIENT_ID": "client-id-is-not-a-guid"})
record_result("Vector 12: Non-UUID client-id rejected", rc != 0, out, "client-id")

# =============================================================================
# SECTION D: AZURE REGION & RESOURCE NAMING VECTORS (13-21)
# =============================================================================
print()
print("--- Section D: Azure Resource Naming Validation ---")

# Vector 13: Region with uppercase characters
rc, out = run_guard({"INPUT_REGION": "EastUS"})
record_result("Vector 13: Azure region with uppercase rejected", rc != 0, out, "region")

# Vector 14: Region with special characters
rc, out = run_guard({"INPUT_REGION": "east-us"})
record_result("Vector 14: Azure region with hyphen rejected", rc != 0, out, "region")

# Vector 15: Resource group ending with period
rc, out = run_guard({"INPUT_AZURE_RG": "rg-invalid."})
record_result("Vector 15: Resource group name ending with period rejected", rc != 0, out, "resource group")

# Vector 16: Resource group exceeding 90 characters
rc, out = run_guard({"INPUT_AZURE_RG": "rg-" + "a" * 89})
record_result("Vector 16: Resource group name > 90 chars rejected", rc != 0, out, "resource group")

# Vector 17: Storage account with hyphens
rc, out = run_guard({"INPUT_AZURE_SA": "st-invalid-01"})
record_result("Vector 17: Storage account name with hyphens rejected", rc != 0, out, "storage-account-name")

# Vector 18: Storage account name too long (>24 chars)
rc, out = run_guard({"INPUT_AZURE_SA": "stinfraflowproductionlongname"})
record_result("Vector 18: Storage account name > 24 chars rejected", rc != 0, out, "storage-account-name")

# Vector 19: Storage account name too short (<3 chars)
rc, out = run_guard({"INPUT_AZURE_SA": "st"})
record_result("Vector 19: Storage account name < 3 chars rejected", rc != 0, out, "storage-account-name")

# Vector 20: Container name starting with hyphen
rc, out = run_guard({"INPUT_AZURE_CONTAINER": "-invalid"})
record_result("Vector 20: Container name starting with hyphen rejected", rc != 0, out, "container")

# Vector 21: Container name with consecutive hyphens
rc, out = run_guard({"INPUT_AZURE_CONTAINER": "tf--state"})
record_result("Vector 21: Container name with consecutive hyphens rejected", rc != 0, out, "container")

# =============================================================================
# SECTION E: STATE KEY & PATH TRAVERSAL VECTORS (22-29)
# =============================================================================
print()
print("--- Section E: Path Traversal & Backend Key Vectors ---")

# Vector 22: State key with path traversal
rc, out = run_guard({"INPUT_AZURE_KEY": "../prod/terraform.tfstate"})
record_result("Vector 22: State blob key with path traversal rejected", rc != 0, out, "path traversal")

# Vector 23: State key with leading slash
rc, out = run_guard({"INPUT_AZURE_KEY": "/smoke/terraform.tfstate"})
record_result("Vector 23: State blob key with leading slash rejected", rc != 0, out, "leading slash")

# Vector 24: Invalid Terraform version format
rc, out = run_guard({"INPUT_VERSION": "latest"})
record_result("Vector 24: Non-semver terraform-version rejected", rc != 0, out, "version")

# Vector 25: Terraform version below minimum (1.6.0)
rc, out = run_guard({"INPUT_VERSION": "1.5.7"})
record_result("Vector 25: Terraform version below 1.6.0 rejected", rc != 0, out, "1.6.0")

# Vector 26: Absolute working directory
rc, out = run_guard({"INPUT_DIR": "/etc/terraform"})
record_result("Vector 26: Absolute working directory rejected", rc != 0, out, "absolute")

# Vector 27: Working directory with path traversal
rc, out = run_guard({"INPUT_DIR": "../../etc/passwd"})
record_result("Vector 27: Working directory path traversal rejected", rc != 0, out, "path traversal")

# Vector 28: Var-file with path traversal
rc, out = run_guard({"INPUT_VAR_FILE": "../secrets.tfvars"})
record_result("Vector 28: Var-file path traversal rejected", rc != 0, out, "path traversal")

# Vector 29: Var-file with absolute path
rc, out = run_guard({"INPUT_VAR_FILE": "/etc/secrets.tfvars"})
record_result("Vector 29: Var-file absolute path rejected", rc != 0, out, "absolute")

# =============================================================================
# SECTION F: OPA / CONFTEST ENTRA OIDC POLICY VECTORS (30-33)
# =============================================================================
print()
print("--- Section F: Entra OIDC OPA Policy Vectors ---")

VALID_ENTRA_INPUT = {
    "federated_identity_credential": {
        "tenant_id": "00000000-0000-0000-0000-000000000002",
        "client_id": "00000000-0000-0000-0000-000000000003",
        "audiences": ["api://AzureADTokenExchange"],
        "subject": "repo:TM-threemavithana/infraflow-consumer-test:environment:smoke",
        "issuer": "https://token.actions.githubusercontent.com",
        "repository": "TM-threemavithana/infraflow-consumer-test",
        "repository_id": "123456789",
        "repository_owner": "TM-threemavithana",
    },
}

# Vector 30: Wildcard audience rejected
bad_input = json.loads(json.dumps(VALID_ENTRA_INPUT))
bad_input["federated_identity_credential"]["audiences"] = ["*"]
rc, out = run_conftest_eval(ENTRA_OIDC_POLICY, "azure.entra_oidc", bad_input)
record_result("Vector 30: Entra OIDC wildcard audience rejected by OPA", rc != 0, out, "wildcard")

# Vector 31: Wrong issuer rejected
bad_input = json.loads(json.dumps(VALID_ENTRA_INPUT))
bad_input["federated_identity_credential"]["issuer"] = "https://evil.example.com"
rc, out = run_conftest_eval(ENTRA_OIDC_POLICY, "azure.entra_oidc", bad_input)
record_result("Vector 31: Entra OIDC wrong issuer rejected by OPA", rc != 0, out, "issuer")

# Vector 32: Repo substitution (expected_repository set, subject doesn't match it)
bad_input = json.loads(json.dumps(VALID_ENTRA_INPUT))
bad_input["expected_repository"] = "TM-threemavithana/infraflow-consumer-test"
bad_input["federated_identity_credential"]["subject"] = "repo:attacker-org/evil-repo:environment:smoke"
rc, out = run_conftest_eval(ENTRA_OIDC_POLICY, "azure.entra_oidc", bad_input)
record_result("Vector 32: Entra OIDC repo substitution rejected by OPA", rc != 0, out, "repo")

# Vector 33: Tenant ID mismatch (expected_tenant_id set, credential has wrong tenant)
bad_input = json.loads(json.dumps(VALID_ENTRA_INPUT))
bad_input["expected_tenant_id"] = "00000000-0000-0000-0000-000000000002"
bad_input["federated_identity_credential"]["tenant_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
rc, out = run_conftest_eval(ENTRA_OIDC_POLICY, "azure.entra_oidc", bad_input)
record_result("Vector 33: Entra OIDC tenant ID mismatch rejected by OPA", rc != 0, out, "tenant")

# =============================================================================
# SECTION G: OPA / CONFTEST STORAGE BACKEND POLICY VECTORS (34-36)
# =============================================================================
print()
print("--- Section G: Azure Storage Backend OPA Policy Vectors ---")

VALID_STORAGE_INPUT = {
    "backend": {
        "azurerm": {
            "storage_account_name": "stinfraflowsmoke01",
            "resource_group_name": "rg-infraflow-smoke",
            "container_name": "tfstate",
            "key": "smoke/terraform.tfstate",
            "use_azuread_auth": True,
        }
    },
    "storage_account": {
        "name": "stinfraflowsmoke01",
        "account_tier": "Standard",
        "account_replication_type": "GRS",
        "min_tls_version": "TLS1_2",
        "allow_nested_items_to_be_public": False,
        "public_network_access_enabled": False,
        "shared_access_key_enabled": False,
        "infrastructure_encryption_enabled": True,
    },
    "role_assignments": [
        {
            "role_definition_name": "Storage Blob Data Contributor",
            "principal_id": "some-service-principal-id",
        }
    ],
}

# Vector 34: Static shared access key enabled — add access_key to backend block
bad_input = json.loads(json.dumps(VALID_STORAGE_INPUT))
bad_input["backend"]["azurerm"]["access_key"] = "raw-secret-key-12345"
rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", bad_input)
record_result("Vector 34: Storage backend with static access_key rejected by OPA", rc != 0, out, "access_key")

# Vector 35: Public access allowed — set in storage_account sub-object
bad_input = json.loads(json.dumps(VALID_STORAGE_INPUT))
bad_input["storage_account"] = {
    "name": "stinfraflowsmoke01",
    "min_tls_version": "TLS1_2",
    "allow_nested_items_to_be_public": True,
    "public_network_access_enabled": False,
    "shared_access_key_enabled": False,
    "infrastructure_encryption_enabled": True,
}
rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", bad_input)
record_result("Vector 35: Storage backend with public blob access rejected by OPA", rc != 0, out, "public")

# Vector 36: Missing TLS enforcement — set TLS1_0 in storage_account
bad_input = json.loads(json.dumps(VALID_STORAGE_INPUT))
bad_input["storage_account"] = {
    "name": "stinfraflowsmoke01",
    "min_tls_version": "TLS1_0",
    "allow_nested_items_to_be_public": False,
    "public_network_access_enabled": False,
    "shared_access_key_enabled": False,
    "infrastructure_encryption_enabled": True,
}
rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", bad_input)
record_result("Vector 36: Storage backend with TLS1_0 (below TLS1_2) rejected by OPA", rc != 0, out, "tls")

# =============================================================================
# FINAL SUMMARY
# =============================================================================
print()
print("==============================================================================")
print(f">>> Azure Negative Security Suite Summary: {passed_tests}/{total_tests} passed")
print("==============================================================================")

if failed_tests:
    print(f"\n[ FAIL ] {len(failed_tests)} test(s) failed:")
    for name, output in failed_tests:
        print(f"  - {name}")
        print(f"    Output: {output[:200]}")
    sys.exit(1)
else:
    print(f"\n[ PASS ] All {total_tests} negative security vectors enforced correctly.")
    sys.exit(0)
