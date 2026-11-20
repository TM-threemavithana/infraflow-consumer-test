#!/usr/bin/env python3
import sys

# Simple YAML block extraction without external dependencies
in_run = False
lines = []
wf_path = sys.argv[1] if len(sys.argv) > 1 else ".infraflow-platform/.github/workflows/reusable-tf-apply.yml"

with open(wf_path, "r", encoding="utf-8") as f:
    for line in f:
        if in_run:
            # Check if block indentation finished
            if line.startswith("  verify-plan:") or (line and not line.startswith("        ") and not line.startswith("          ") and not line.strip() == ""):
                break
            lines.append(line)
        elif "run: |" in line and "Validate & Guard Apply Simulation Inputs" not in line:
            in_run = True

print("".join(lines).strip())
