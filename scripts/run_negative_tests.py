#!/usr/bin/env python3
"""
InfraFlow G06.6 — External Consumer Negative Security Integration Suite.
Validates that invalid, tampered, expired, replayed, or unauthorized plans are strictly rejected.
"""

import os
import sys
import json
import subprocess
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "artifacts")
FIXTURES_DIR = os.path.join(REPO_ROOT, "fixtures", "negative")

# Path to platform tools (can be checked out locally or via .infraflow-platform in CI)
if os.path.isdir(os.path.join(REPO_ROOT, ".infraflow-platform", "scripts")):
    PLATFORM_SCRIPTS = os.path.join(REPO_ROOT, ".infraflow-platform", "scripts")
elif os.path.isdir("/home/tharuka/projects/infraflow/scripts"):
    PLATFORM_SCRIPTS = "/home/tharuka/projects/infraflow/scripts"
else:
    raise RuntimeError("Cannot find platform scripts directory")

VERIFY_LIFECYCLE_PY = os.path.join(PLATFORM_SCRIPTS, "verify-plan-lifecycle.py")
KMS_ENVELOPE_PY = os.path.join(PLATFORM_SCRIPTS, "kms-envelope.py")
ASSESS_DESTRUCTION_PY = os.path.join(PLATFORM_SCRIPTS, "assess-destruction.py")
VERIFY_INTEGRITY_PY = os.path.join(PLATFORM_SCRIPTS, "verify-plan-integrity.py")

VALID_REPO = "TM-threemavithana/infraflow-consumer-test"
VALID_COMMIT = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
VALID_ENV = "test-environment"
VALID_LINEAGE = "3f2e1d0c-4b5a-6789-0123-abcdef456789"
VALID_SERIAL = "42"
VALID_WORKSPACE = "default"
VALID_BACKEND = "s3://infraflow-consumer-tfstate/env/test/tf.state"
VALID_DIGEST = "9d9b2a3254817284a5d88e8cbdb351f2a8a84365db2c6987dc380d94046714b6"

total_tests = 0
passed_tests = 0
failed_tests = []


def record_result(name: str, expected_rejected: bool, exit_code: int, output: str, expected_snippet: str):
    global total_tests, passed_tests
    total_tests += 1
    
    is_rejected = (exit_code != 0) or ("REJECTED" in output)
    snippet_matched = expected_snippet.lower() in output.lower()

    if expected_rejected and is_rejected and snippet_matched:
        passed_tests += 1
        print(f"  [ PASS ] {name} (Rejected as expected: '{expected_snippet}')")
    else:
        failed_tests.append((name, exit_code, output))
        print(f"  [ FAIL ] {name}")
        print(f"          Exit Code: {exit_code}")
        print(f"          Expected Snippet: '{expected_snippet}'")
        print(f"          Output Preview: {output[:300]}")


print("==============================================================================")
print(">>> InfraFlow G06.6 External Negative Security Integration Suite")
print("==============================================================================")

tmp_ledger = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name

try:
    # 1. Expired Plan
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(FIXTURES_DIR, "plan_expired.enc.json"),
            "--state-file", os.path.join(ARTIFACTS_DIR, "terraform.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 01: Expired Plan Rejected", True, res.returncode, res.stdout + res.stderr, "PLAN_EXPIRED")

    # 2. Tampered Ciphertext
    res = subprocess.run(
        [
            sys.executable, KMS_ENVELOPE_PY, "decrypt",
            "--envelope-file", os.path.join(FIXTURES_DIR, "plan_tampered_ciphertext.enc.json"),
            "--output-plan", "/tmp/tampered_out.bin",
            "--kek-hex", "01" * 32,
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 02: Tampered Ciphertext Rejected", True, res.returncode, res.stdout + res.stderr, "EnvelopeAuthenticationError")

    # 3. Incorrect Plan Digest
    res = subprocess.run(
        [
            sys.executable, KMS_ENVELOPE_PY, "decrypt",
            "--envelope-file", os.path.join(FIXTURES_DIR, "plan_bad_digest.enc.json"),
            "--output-plan", "/tmp/bad_digest_out.bin",
            "--kek-hex", "01" * 32,
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 03: Incorrect Plan Digest Rejected", True, res.returncode, res.stdout + res.stderr, "Envelope")

    # 4. Invalid Provenance
    res = subprocess.run(
        [
            sys.executable, VERIFY_INTEGRITY_PY, "verify-provenance",
            "--provenance", os.path.join(FIXTURES_DIR, "invalid_provenance.json"),
            "--expected-repository", VALID_REPO,
            "--expected-commit-sha", VALID_COMMIT
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 04: Invalid Provenance Rejected", True, res.returncode, res.stdout + res.stderr, "Provenance")

    # 5. Wrong Repository
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(FIXTURES_DIR, "plan_bad_repo.enc.json"),
            "--state-file", os.path.join(ARTIFACTS_DIR, "terraform.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 05: Wrong Repository Rejected", True, res.returncode, res.stdout + res.stderr, "REPO_MISMATCH")

    # 6. Wrong Commit
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(FIXTURES_DIR, "plan_bad_commit.enc.json"),
            "--state-file", os.path.join(ARTIFACTS_DIR, "terraform.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 06: Wrong Commit SHA Rejected", True, res.returncode, res.stdout + res.stderr, "COMMIT_MISMATCH")

    # 7. State Lineage Mismatch
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(ARTIFACTS_DIR, "plan.enc.json"),
            "--state-file", os.path.join(FIXTURES_DIR, "state_bad_lineage.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 07: State Lineage Mismatch Rejected", True, res.returncode, res.stdout + res.stderr, "STATE_LINEAGE_MISMATCH")

    # 8. State Serial Mismatch
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(ARTIFACTS_DIR, "plan.enc.json"),
            "--state-file", os.path.join(FIXTURES_DIR, "state_stale_serial.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 08: State Serial Mismatch Rejected", True, res.returncode, res.stdout + res.stderr, "STATE_SERIAL_REGRESSION")

    # 9. Missing Destruction Confirmation
    res = subprocess.run(
        [
            sys.executable, ASSESS_DESTRUCTION_PY, "assess",
            "--plan-file", os.path.join(FIXTURES_DIR, "plan_destructive.json"),
            "--expected-plan-id", "plan-destruct-01",
            "--expected-digest", VALID_DIGEST,
            "--expected-repo", VALID_REPO,
            "--environment", VALID_ENV,
            "--policy-file", os.path.join(ARTIFACTS_DIR, "destruction-policy.json")
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 09: Missing Destruction Confirmation Rejected", True, res.returncode, res.stdout + res.stderr, "MISSING_DESTRUCTION_CONFIRMATION")

    # 10. Untrusted Authorizer
    res = subprocess.run(
        [
            sys.executable, ASSESS_DESTRUCTION_PY, "assess",
            "--plan-file", os.path.join(FIXTURES_DIR, "plan_destructive.json"),
            "--expected-plan-id", "plan-consumer-smoke-01",
            "--expected-digest", VALID_DIGEST,
            "--expected-repo", VALID_REPO,
            "--environment", VALID_ENV,
            "--policy-file", os.path.join(ARTIFACTS_DIR, "destruction-policy.json"),
            "--confirmation-file", os.path.join(FIXTURES_DIR, "untrusted_token.json"),
            "--trusted-authorizers", "sec-lead@company.internal"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 10: Untrusted Authorizer Rejected", True, res.returncode, res.stdout + res.stderr, "UNAUTHORIZED_AUTHORIZER")

    # 11. Excessive Deletion Threshold (Policy Elevation)
    res = subprocess.run(
        [
            sys.executable, ASSESS_DESTRUCTION_PY, "assess",
            "--plan-file", os.path.join(FIXTURES_DIR, "plan_destructive.json"),
            "--expected-plan-id", "plan-consumer-smoke-01",
            "--expected-digest", VALID_DIGEST,
            "--expected-repo", VALID_REPO,
            "--environment", "production",
            "--policy-file", os.path.join(FIXTURES_DIR, "policy_excessive.json")
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 11: Excessive Deletion Ceiling Rejected", True, res.returncode, res.stdout + res.stderr, "POLICY_CEILING_EXCEEDED")

    # 12. Replayed Plan Identifier
    # Step A: First reservation succeeds
    subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(ARTIFACTS_DIR, "plan.enc.json"),
            "--state-file", os.path.join(ARTIFACTS_DIR, "terraform.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    # Step B: Second reservation of identical plan ID is rejected as duplicate
    res = subprocess.run(
        [
            sys.executable, VERIFY_LIFECYCLE_PY, "verify",
            "--envelope-file", os.path.join(ARTIFACTS_DIR, "plan.enc.json"),
            "--state-file", os.path.join(ARTIFACTS_DIR, "terraform.tfstate"),
            "--expected-repo", VALID_REPO,
            "--expected-commit", VALID_COMMIT,
            "--expected-environment", VALID_ENV,
            "--expected-lineage", VALID_LINEAGE,
            "--expected-serial", VALID_SERIAL,
            "--ledger-db", tmp_ledger,
            "--provenance-status", "VERIFIED"
        ],
        capture_output=True, text=True
    )
    record_result("Scenario 12: Replayed Plan ID Rejected", True, res.returncode, res.stdout + res.stderr, "DUPLICATE_RESERVATION")

finally:
    if os.path.exists(tmp_ledger):
        os.remove(tmp_ledger)

print("------------------------------------------------------------------------------")
print(f"Results: {passed_tests} / {total_tests} negative security scenarios rejected as expected")
print("==============================================================================")

if failed_tests:
    print(f"FAILED: {len(failed_tests)} negative tests did NOT reject as expected!")
    sys.exit(1)

print("SUCCESS: All 12 negative security scenarios strictly rejected (fail-closed)!")
sys.exit(0)
