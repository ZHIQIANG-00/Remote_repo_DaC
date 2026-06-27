#!/usr/bin/env python3
"""
logtest_runner.py - behavioral tests for Wazuh rules/decoders.

Each test case (YAML, under tests/cases/) sends one log line to
`wazuh-logtest --output json` inside a running Wazuh manager container and
asserts the resulting decode/rule outcome. Exits non-zero if any case fails,
so the GitHub Actions job blocks the PR.

Test case schema (a YAML list of mappings):

  - name: "human readable description"     # optional
    log:  "the raw log line to feed in"    # required
    expect:                                # omit when using expect_no_rule
      rule_id:  "100001"                   # exact rule id
      level:    5                          # exact alert level
      min_level: 3                         # level must be >= this
      max_level: 5                         # level must be <= this
      decoder:  "sshd"                     # matched decoder name
      groups:   ["authentication_failed"]  # these groups must all be present
    expect_no_rule: false                  # set true to assert nothing fires
"""

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path

import yaml


def _extract_json_objects(text: str) -> list:
    """Pull every top-level JSON object out of mixed text (banner + json)."""
    objs = []
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        brace = text.find("{", idx)
        if brace == -1:
            break
        try:
            obj, end = dec.raw_decode(text, brace)
            objs.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx = brace + 1
    return objs


def run_logtest(container: str, event: str):
    """Feed one event to wazuh-logtest. Returns (result_dict_or_None, raw_text)."""
    cmd = [
        "docker", "exec", "-i", container,
        "/var/ossec/bin/wazuh-logtest", "--output", "json",
    ]
    proc = subprocess.run(cmd, input=event + "\n", capture_output=True, text=True)
    raw = (proc.stdout or "") + (proc.stderr or "")

    # wazuh-logtest may print a session message AND the result. Pick the JSON
    # object that actually looks like a logtest result (has rule/decoder info).
    objs = _extract_json_objects(raw)
    for obj in objs:
        if isinstance(obj, dict) and any(k in obj for k in ("rule", "decoder", "predecoder")):
            return obj, raw
    return None, raw


def check_case(result, case: dict) -> list:
    """Return a list of failure messages for one case (empty list == pass)."""
    failures = []
    rule = (result or {}).get("rule")

    if case.get("expect_no_rule", False):
        if rule is not None:
            failures.append(f"expected no rule, but {rule.get('id')} fired")
        return failures

    if rule is None:
        failures.append("expected a rule to match, but none did")
        return failures

    exp = case.get("expect", {}) or {}
    level = int(rule.get("level", -1))

    if "rule_id" in exp and str(rule.get("id")) != str(exp["rule_id"]):
        failures.append(f"rule_id: expected {exp['rule_id']}, got {rule.get('id')}")
    if "level" in exp and level != int(exp["level"]):
        failures.append(f"level: expected {exp['level']}, got {level}")
    if "min_level" in exp and level < int(exp["min_level"]):
        failures.append(f"min_level: expected >= {exp['min_level']}, got {level}")
    if "max_level" in exp and level > int(exp["max_level"]):
        failures.append(f"max_level: expected <= {exp['max_level']}, got {level}")
    if "decoder" in exp:
        got = (result.get("decoder") or {}).get("name")
        if got != exp["decoder"]:
            failures.append(f"decoder: expected {exp['decoder']}, got {got}")
    if "groups" in exp:
        got_groups = set(rule.get("groups", []))
        missing = set(exp["groups"]) - got_groups
        if missing:
            failures.append(f"groups: missing {sorted(missing)} (got {sorted(got_groups)})")

    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="wazuh-test")
    ap.add_argument("--tests", default="tests/cases")
    args = ap.parse_args()

    files = sorted(
        glob.glob(f"{args.tests}/**/*.yml", recursive=True)
        + glob.glob(f"{args.tests}/**/*.yaml", recursive=True)
    )
    if not files:
        print(f"No test files found under {args.tests}/ - nothing to check.")
        return 0

    total = passed = 0
    for f in files:
        cases = yaml.safe_load(Path(f).read_text()) or []
        for case in cases:
            total += 1
            result, raw = run_logtest(args.container, case["log"])
            failures = check_case(result, case)
            name = case.get("name") or case["log"][:60]
            if failures:
                print(f"FAIL  {name}")
                for msg in failures:
                    print(f"        - {msg}")
                # Show what logtest actually returned, to make debugging easy.
                print("        --- raw logtest output ---")
                for line in raw.strip().splitlines():
                    print(f"        | {line}")
                print("        ---------------------------")
            else:
                passed += 1
                print(f"PASS  {name}")

    print(f"\n{passed}/{total} cases passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())