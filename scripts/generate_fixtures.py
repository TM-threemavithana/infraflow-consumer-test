#!/usr/bin/env python3
"""
Generate reproducible synthetic input fixtures for InfraFlow G06 protected apply simulation.
Includes positive valid fixtures and negative attack scenario fixtures.
"""

import os
import sys
import json
import base64
import hashlib
import datetime
import importlib.util

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "artifacts")
FIXTURES_DIR = os.path.join(REPO_ROOT, "fixtures", "negative")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(FIXTURES_DIR, exist_ok=True)

# Import platform tooling
PLATFORM_SCRIPTS = "/home/tharuka/projects/infraflow/scripts"
def load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

kms_mod = load_mod("kms_envelope", os.path.join(PLATFORM_SCRIPTS, "kms-envelope.py"))
integrity_mod = load_mod("verify_plan_integrity", os.path.join(PLATFORM_SCRIPTS, "verify-plan-integrity.py"))
assess_mod = load_mod("assess_destruction", os.path.join(PLATFORM_SCRIPTS, "assess-destruction.py"))

encrypt_plan = kms_mod.encrypt_plan
PlanEnvelope = kms_mod.PlanEnvelope
sign_provenance = integrity_mod.sign_provenance
DestructionConfirmationValidator = assess_mod.DestructionConfirmationValidator

# Context configuration
REPO_NAME = "TM-threemavithana/infraflow-consumer-test"
VALID_COMMIT = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
ENV_NAME = "test-environment"
PLAN_ID = "plan-consumer-smoke-01"
LINEAGE = "3f2e1d0c-4b5a-6789-0123-abcdef456789"
SERIAL = 42
BACKEND = "s3://infraflow-consumer-tfstate/env/test/tf.state"
WORKSPACE = "default"

now = datetime.datetime.now(datetime.timezone.utc)
created_at_iso = now.isoformat()
expires_at_iso = (now + datetime.timedelta(hours=12)).isoformat()
expired_at_iso = (now - datetime.timedelta(hours=2)).isoformat()

# 1. Binary Plan File & Digest
sample_plan_bytes = b"TERRAFORM_BINARY_PLAN_SYNTHETIC_DATA_FOR_CONSUMER_SMOKE_TEST\x00\x01\x02\xff"
plan_digest = hashlib.sha256(sample_plan_bytes).hexdigest()
with open(os.path.join(ARTIFACTS_DIR, "plan.bin"), "wb") as f:
    f.write(sample_plan_bytes)

# 2. Plan JSON (Safe: 1 resource create)
plan_json_content = {
    "format_version": "1.2",
    "terraform_version": "1.10.4",
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "local_file.smoke_test",
                    "mode": "managed",
                    "type": "local_file",
                    "name": "smoke_test",
                    "provider_name": "registry.terraform.io/hashicorp/local",
                    "values": {"content": "smoke test", "filename": "smoke.txt"}
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "local_file.smoke_test",
            "mode": "managed",
            "type": "local_file",
            "name": "smoke_test",
            "provider_name": "registry.terraform.io/hashicorp/local",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"content": "smoke test", "filename": "smoke.txt"},
                "after_unknown": {}
            }
        }
    ],
    "configuration": {"root_module": {}}
}
plan_json_path = os.path.join(ARTIFACTS_DIR, "plan.json")
with open(plan_json_path, "w", encoding="utf-8") as f:
    json.dump(plan_json_content, f, indent=2)

# 3. State JSON
state_json_content = {
    "version": 4,
    "terraform_version": "1.10.4",
    "serial": SERIAL,
    "lineage": LINEAGE,
    "outputs": {},
    "resources": []
}
with open(os.path.join(ARTIFACTS_DIR, "terraform.tfstate"), "w", encoding="utf-8") as f:
    json.dump(state_json_content, f, indent=2)

# 4. KMS Mock Key & Encryption
mock_kek = b"\x01" * 32
mock_key_id = "mock-kms-kek-1"
valid_envelope = encrypt_plan(
    plan_bytes=sample_plan_bytes,
    kek=mock_kek,
    key_id=mock_key_id,
    repository=REPO_NAME,
    commit_sha=VALID_COMMIT,
    workflow=".github/workflows/infraflow-protected-apply-simulation.yml",
    environment=ENV_NAME,
    plan_identifier=PLAN_ID
)

# Convert to dict and add expiration info if needed
envelope_dict = valid_envelope.to_dict()
envelope_dict["created_at"] = created_at_iso
envelope_dict["expires_at"] = expires_at_iso
envelope_dict["execution_context"] = {
    "terraform_version": "1.10.4",
    "backend": BACKEND,
    "workspace": WORKSPACE
}

with open(os.path.join(ARTIFACTS_DIR, "plan.enc.json"), "w", encoding="utf-8") as f:
    json.dump(envelope_dict, f, indent=2)

# 5. Provenance Attestation
provenance_path = os.path.join(ARTIFACTS_DIR, "plan-provenance.json")
sign_provenance(
    plan_json_path=plan_json_path,
    output_path=provenance_path,
    repository=REPO_NAME,
    commit_sha=VALID_COMMIT,
    workflow=".github/workflows/infraflow-protected-apply-simulation.yml",
    policy_result="passed",
    signing_tier="standard"
)

# 6. Destruction Blast-Radius Policy
destruction_policy = {
    "schema_version": "infraflow-destruction-policy-v1",
    "policy_name": "consumer-smoke-policy",
    "max_deletions": 5,
    "max_replacements": 10,
    "allow_state_wide_destroy": False,
    "protected_resources": ["aws_iam_role.*", "aws_kms_key.*"],
    "trusted_authorizers": ["sec-lead@company.internal", "release-bot@company.internal"]
}
with open(os.path.join(ARTIFACTS_DIR, "destruction-policy.json"), "w", encoding="utf-8") as f:
    json.dump(destruction_policy, f, indent=2)

# ==============================================================================
# NEGATIVE FIXTURES
# ==============================================================================

# Negative 1: Expired Plan
expired_dict = dict(envelope_dict)
expired_dict["created_at"] = (now - datetime.timedelta(hours=14)).isoformat()
expired_dict["expires_at"] = expired_at_iso
with open(os.path.join(FIXTURES_DIR, "plan_expired.enc.json"), "w", encoding="utf-8") as f:
    json.dump(expired_dict, f, indent=2)

# Negative 2: Tampered Ciphertext
tampered_dict = dict(envelope_dict)
raw_ct = base64.b64decode(tampered_dict["ciphertext"])
tampered_ct = bytes([raw_ct[0] ^ 0x01]) + raw_ct[1:]
tampered_dict["ciphertext"] = base64.b64encode(tampered_ct).decode("ascii")
with open(os.path.join(FIXTURES_DIR, "plan_tampered_ciphertext.enc.json"), "w", encoding="utf-8") as f:
    json.dump(tampered_dict, f, indent=2)

# Negative 3: Incorrect Plan Digest
bad_digest_dict = dict(envelope_dict)
bad_digest_dict["plan_digest"] = "0" * 64
bad_digest_dict["plan_digest_sha256"] = "0" * 64
if "aad" in bad_digest_dict and isinstance(bad_digest_dict["aad"], dict):
    bad_digest_dict["aad"]["plan_digest_sha256"] = "0" * 64
    bad_digest_dict["aad"]["plan_digest"] = "0" * 64
with open(os.path.join(FIXTURES_DIR, "plan_bad_digest.enc.json"), "w", encoding="utf-8") as f:
    json.dump(bad_digest_dict, f, indent=2)

# Negative 4: Wrong Repository
bad_repo_env = encrypt_plan(
    plan_bytes=sample_plan_bytes,
    kek=mock_kek,
    key_id=mock_key_id,
    repository="attacker/malicious-repo",
    commit_sha=VALID_COMMIT,
    workflow=".github/workflows/infraflow-protected-apply-simulation.yml",
    environment=ENV_NAME,
    plan_identifier="plan-bad-repo-01"
)
bad_repo_dict = bad_repo_env.to_dict()
bad_repo_dict["expires_at"] = expires_at_iso
with open(os.path.join(FIXTURES_DIR, "plan_bad_repo.enc.json"), "w", encoding="utf-8") as f:
    json.dump(bad_repo_dict, f, indent=2)

# Negative 5: Wrong Commit SHA
bad_commit_env = encrypt_plan(
    plan_bytes=sample_plan_bytes,
    kek=mock_kek,
    key_id=mock_key_id,
    repository=REPO_NAME,
    commit_sha="0000000000000000000000000000000000000000",
    workflow=".github/workflows/infraflow-protected-apply-simulation.yml",
    environment=ENV_NAME,
    plan_identifier="plan-bad-commit-01"
)
bad_commit_dict = bad_commit_env.to_dict()
bad_commit_dict["expires_at"] = expires_at_iso
with open(os.path.join(FIXTURES_DIR, "plan_bad_commit.enc.json"), "w", encoding="utf-8") as f:
    json.dump(bad_commit_dict, f, indent=2)

# Negative 6: State Lineage Mismatch
state_bad_lineage = dict(state_json_content)
state_bad_lineage["lineage"] = "99999999-9999-9999-9999-999999999999"
with open(os.path.join(FIXTURES_DIR, "state_bad_lineage.tfstate"), "w", encoding="utf-8") as f:
    json.dump(state_bad_lineage, f, indent=2)

# Negative 7: State Serial Mismatch (Stale serial 41)
state_stale_serial = dict(state_json_content)
state_stale_serial["serial"] = 41
with open(os.path.join(FIXTURES_DIR, "state_stale_serial.tfstate"), "w", encoding="utf-8") as f:
    json.dump(state_stale_serial, f, indent=2)

# Negative 8: Destructive Plan Without Confirmation (1 create + 1 delete so not statewide destroy)
destructive_plan = {
    "format_version": "1.2",
    "terraform_version": "1.10.4",
    "resource_changes": [
        {
            "address": "local_file.smoke_test",
            "mode": "managed",
            "type": "local_file",
            "name": "smoke_test",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"content": "smoke", "filename": "smoke.txt"}
            }
        },
        {
            "address": "aws_s3_bucket.data",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "data",
            "change": {
                "actions": ["delete"],
                "before": {"bucket": "my-data-bucket"},
                "after": None
            }
        }
    ]
}
with open(os.path.join(FIXTURES_DIR, "plan_destructive.json"), "w", encoding="utf-8") as f:
    json.dump(destructive_plan, f, indent=2)

# Negative 9: Policy Ceiling Elevation (>25 deletions)
policy_excessive = {
    "schema_version": "infraflow-destruction-policy-v1",
    "policy_name": "excessive-policy",
    "max_deletions": 50,  # exceeds platform ceiling 25
    "max_replacements": 10
}
with open(os.path.join(FIXTURES_DIR, "policy_excessive.json"), "w", encoding="utf-8") as f:
    json.dump(policy_excessive, f, indent=2)

# Negative 10: Invalid Provenance
with open(os.path.join(FIXTURES_DIR, "invalid_provenance.json"), "w", encoding="utf-8") as f:
    json.dump({"payload": "forged", "signatures": [{"sig": "invalid"}]}, f, indent=2)

# Negative 11: Untrusted Authorizer Confirmation Token
untrusted_token = DestructionConfirmationValidator.create_token(
    plan_id=PLAN_ID,
    plan_digest_sha256=plan_digest,
    source_repository=REPO_NAME,
    target_environment=ENV_NAME,
    pure_deletions=1,
    replacements=0,
    authorized_by="mallory@untrusted.attacker",
    validity_seconds=3600,
    current_time=now
)
with open(os.path.join(FIXTURES_DIR, "untrusted_token.json"), "w", encoding="utf-8") as f:
    json.dump(untrusted_token, f, indent=2)

print("Successfully generated all positive and negative fixtures!")
