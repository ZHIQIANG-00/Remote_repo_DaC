# #!/usr/bin/env python3
# """
# logtest_runner.py - behavioral tests for Wazuh rules/decoders via the Wazuh API.

# Talks to the manager's /logtest endpoint (stable JSON response across versions)
# instead of the wazuh-logtest CLI, whose flags vary by version. For each test
# case (YAML, under tests/cases/) it sends one log line and asserts the resulting
# decode/rule outcome. Exits non-zero if any case fails, so the CI job blocks the PR.

# Requires the manager API to be reachable at https://localhost:55000 (the workflow
# publishes that port from the container). Uses only the standard library + pyyaml.

# Test case schema (a YAML list of mappings):

#   - name: "human readable description"     # optional
#     log:  "the raw log line to feed in"    # required
#     log_format: syslog                     # optional, default "syslog" (use "json" for JSON logs)
#     expect:                                # omit when using expect_no_rule
#       rule_id:  "100001"                   # exact rule id
#       level:    5                          # exact alert level
#       min_level: 3                         # level must be >= this
#       max_level: 5                         # level must be <= this
#       decoder:  "sshd"                     # matched decoder name
#       groups:   ["authentication_failed"]  # these groups must all be present
#     expect_no_rule: false                  # set true to assert NOTHING fires at all
#     expect_no_alert: false                 # set true to allow level-0 info rules but no real alert
# """

# import argparse
# import base64
# import glob
# import json
# import os
# import ssl
# import sys
# import time
# import urllib.error
# import urllib.request
# from pathlib import Path

# import yaml

# API = "https://localhost:55000"

# # The manager uses a self-signed cert; skip verification for this local call.
# _CTX = ssl.create_default_context()
# _CTX.check_hostname = False
# _CTX.verify_mode = ssl.CERT_NONE


# def _request(method, path, token=None, basic=None, body=None):
#     url = API + path
#     data = json.dumps(body).encode() if body is not None else None
#     req = urllib.request.Request(url, data=data, method=method)
#     if body is not None:
#         req.add_header("Content-Type", "application/json")
#     if token:
#         req.add_header("Authorization", f"Bearer {token}")
#     if basic:
#         creds = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
#         req.add_header("Authorization", f"Basic {creds}")
#     with urllib.request.urlopen(req, context=_CTX, timeout=30) as resp:
#         return resp.read().decode()


# def get_token(user, password, retries=20, delay=3):
#     """Log in to the API and return a JWT. Retries while the API is still waking up."""
#     last = None
#     for _ in range(retries):
#         try:
#             tok = _request("POST", "/security/user/authenticate?raw=true",
#                            basic=(user, password)).strip()
#             if tok:
#                 return tok
#         except Exception as e:  # noqa: BLE001 - want any failure to retry
#             last = e
#             time.sleep(delay)
#     raise RuntimeError(f"could not authenticate to Wazuh API as '{user}': {last}")


# def run_logtest(token, event, log_format="syslog", location="logtest"):
#     """Send one event to /logtest. Returns (output_dict, raw_text)."""
#     body = {"log_format": log_format, "location": location, "event": event}
#     raw = _request("PUT", "/logtest", token=token, body=body)
#     try:
#         resp = json.loads(raw)
#     except json.JSONDecodeError:
#         return None, raw
#     output = (resp.get("data") or {}).get("output") or {}
#     return output, raw


# def check_case(result, case):
#     failures = []
#     rule = (result or {}).get("rule")

#     if case.get("expect_no_rule", False):
#         if rule is not None:
#             failures.append(f"expected no rule, but {rule.get('id')} fired")
#         return failures

#     # "expect_no_alert" passes when nothing fires OR only an informational
#     # level-0 rule fires (e.g. Wazuh's harmless "USB messages grouped." rule).
#     # It fails only if a real, alert-level rule (level >= 1) matches.
#     if case.get("expect_no_alert", False):
#         if rule is not None and int(rule.get("level", 0)) >= 1:
#             failures.append(
#                 f"expected no alert, but rule {rule.get('id')} "
#                 f"fired at level {rule.get('level')}"
#             )
#         return failures

#     if rule is None:
#         failures.append("expected a rule to match, but none did")
#         return failures

#     exp = case.get("expect", {}) or {}
#     level = int(rule.get("level", -1))

#     if "rule_id" in exp and str(rule.get("id")) != str(exp["rule_id"]):
#         failures.append(f"rule_id: expected {exp['rule_id']}, got {rule.get('id')}")
#     if "level" in exp and level != int(exp["level"]):
#         failures.append(f"level: expected {exp['level']}, got {level}")
#     if "min_level" in exp and level < int(exp["min_level"]):
#         failures.append(f"min_level: expected >= {exp['min_level']}, got {level}")
#     if "max_level" in exp and level > int(exp["max_level"]):
#         failures.append(f"max_level: expected <= {exp['max_level']}, got {level}")
#     if "decoder" in exp:
#         got = (result.get("decoder") or {}).get("name")
#         if got != exp["decoder"]:
#             failures.append(f"decoder: expected {exp['decoder']}, got {got}")
#     if "groups" in exp:
#         got_groups = set(rule.get("groups", []))
#         missing = set(exp["groups"]) - got_groups
#         if missing:
#             failures.append(f"groups: missing {sorted(missing)} (got {sorted(got_groups)})")

#     return failures


# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("--container", default="wazuh-test")  # kept for compatibility; unused
#     ap.add_argument("--tests", default="tests/cases")
#     ap.add_argument("--api-user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
#     ap.add_argument("--api-password", default=os.environ.get("WAZUH_API_PASSWORD", "wazuh"))
#     args = ap.parse_args()

#     files = sorted(
#         glob.glob(f"{args.tests}/**/*.yml", recursive=True)
#         + glob.glob(f"{args.tests}/**/*.yaml", recursive=True)
#     )
#     if not files:
#         print(f"No test files found under {args.tests}/ - nothing to check.")
#         return 0

#     print("Authenticating to Wazuh API ...")
#     token = get_token(args.api_user, args.api_password)
#     print("Authenticated.\n")

#     total = passed = 0
#     for f in files:
#         cases = yaml.safe_load(Path(f).read_text()) or []
#         for case in cases:
#             total += 1
#             result, raw = run_logtest(
#                 token, case["log"], log_format=case.get("log_format", "syslog")
#             )
#             failures = check_case(result, case)
#             name = case.get("name") or case["log"][:60]
#             if failures:
#                 print(f"FAIL  {name}")
#                 for msg in failures:
#                     print(f"        - {msg}")
#                 print("        --- raw /logtest response ---")
#                 for line in raw.strip().splitlines():
#                     print(f"        | {line}")
#                 print("        -----------------------------")
#             else:
#                 passed += 1
#                 print(f"PASS  {name}")

#     print(f"\n{passed}/{total} cases passed")
#     return 0 if passed == total else 1


# if __name__ == "__main__":
#     sys.exit(main())


#!/usr/bin/env python3
"""
logtest_runner.py - behavioral tests for Wazuh rules/decoders via the Wazuh API.

Talks to the manager's /logtest endpoint (stable JSON response across versions)
instead of the wazuh-logtest CLI, whose flags vary by version. For each test
case (YAML, under tests/cases/) it sends one log line and asserts the resulting
decode/rule outcome. Exits non-zero if any case fails, so the CI job blocks the PR.

Requires the manager API to be reachable at https://localhost:55000 (the workflow
publishes that port from the container). Uses only the standard library + pyyaml.

Test case schema (a YAML list of mappings):

  - name: "human readable description"     # optional
    log:  "the raw log line to feed in"    # required
    log_format: syslog                     # optional, default "syslog" (use "json" for JSON logs)
    expect:                                # omit when using expect_no_rule
      rule_id:  "100001"                   # exact rule id
      level:    5                          # exact alert level
      min_level: 3                         # level must be >= this
      max_level: 5                         # level must be <= this
      decoder:  "sshd"                     # matched decoder name
      groups:   ["authentication_failed"]  # these groups must all be present
      fields:                              # decoded field values (from the decoder)
        signature: "VI:NEW-LINK"           #   asserts output.data.signature == "VI:NEW-LINK"
        srcip: "192.168.50.187"
    expect_no_rule: false                  # set true to assert NOTHING fires at all
    expect_no_alert: false                 # set true to allow level-0 info rules but no real alert
"""

import argparse
import base64
import glob
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

API = "https://localhost:55000"

# The manager uses a self-signed cert; skip verification for this local call.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _request(method, path, token=None, basic=None, body=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if basic:
        creds = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
    with urllib.request.urlopen(req, context=_CTX, timeout=30) as resp:
        return resp.read().decode()


def get_token(user, password, retries=20, delay=3):
    """Log in to the API and return a JWT. Retries while the API is still waking up."""
    last = None
    for _ in range(retries):
        try:
            tok = _request("POST", "/security/user/authenticate?raw=true",
                           basic=(user, password)).strip()
            if tok:
                return tok
        except Exception as e:  # noqa: BLE001 - want any failure to retry
            last = e
            time.sleep(delay)
    raise RuntimeError(f"could not authenticate to Wazuh API as '{user}': {last}")


def run_logtest(token, event, log_format="syslog", location="logtest"):
    """Send one event to /logtest. Returns (output_dict, raw_text)."""
    body = {"log_format": log_format, "location": location, "event": event}
    raw = _request("PUT", "/logtest", token=token, body=body)
    try:
        resp = json.loads(raw)
    except json.JSONDecodeError:
        return None, raw
    output = (resp.get("data") or {}).get("output") or {}
    return output, raw


def check_case(result, case):
    failures = []
    rule = (result or {}).get("rule")

    if case.get("expect_no_rule", False):
        if rule is not None:
            failures.append(f"expected no rule, but {rule.get('id')} fired")
        return failures

    # "expect_no_alert" passes when nothing fires OR only an informational
    # level-0 rule fires (e.g. Wazuh's harmless "USB messages grouped." rule).
    # It fails only if a real, alert-level rule (level >= 1) matches.
    if case.get("expect_no_alert", False):
        if rule is not None and int(rule.get("level", 0)) >= 1:
            failures.append(
                f"expected no alert, but rule {rule.get('id')} "
                f"fired at level {rule.get('level')}"
            )
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
    if "fields" in exp:
        # Decoder output: assert values the decoder extracted (under output.data).
        got_fields = result.get("data") or {}
        for k, v in exp["fields"].items():
            if str(got_fields.get(k)) != str(v):
                failures.append(f"field '{k}': expected '{v}', got '{got_fields.get(k)}'")

    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="wazuh-test")  # kept for compatibility; unused
    ap.add_argument("--tests", default="tests/cases")
    ap.add_argument("--api-user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
    ap.add_argument("--api-password", default=os.environ.get("WAZUH_API_PASSWORD", "wazuh"))
    args = ap.parse_args()

    files = sorted(
        glob.glob(f"{args.tests}/**/*.yml", recursive=True)
        + glob.glob(f"{args.tests}/**/*.yaml", recursive=True)
    )
    if not files:
        print(f"No test files found under {args.tests}/ - nothing to check.")
        return 0

    print("Authenticating to Wazuh API ...")
    token = get_token(args.api_user, args.api_password)
    print("Authenticated.\n")

    total = passed = 0
    for f in files:
        cases = yaml.safe_load(Path(f).read_text()) or []
        for case in cases:
            total += 1
            result, raw = run_logtest(
                token, case["log"], log_format=case.get("log_format", "syslog")
            )
            failures = check_case(result, case)
            name = case.get("name") or case["log"][:60]
            if failures:
                print(f"FAIL  {name}")
                for msg in failures:
                    print(f"        - {msg}")
                print("        --- raw /logtest response ---")
                for line in raw.strip().splitlines():
                    print(f"        | {line}")
                print("        -----------------------------")
            else:
                passed += 1
                print(f"PASS  {name}")

    print(f"\n{passed}/{total} cases passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())