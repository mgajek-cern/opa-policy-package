#!/usr/bin/env python3
"""
ingest_policies.py — load Rego policies and optional data into a running OPA server.

Usage:
    python ingest_policies.py [--opa-url URL] [--admins alice,bob]

Options:
    --opa-url    Base URL of the OPA server  (default: http://localhost:8181)
    --admins     Comma-separated list of Rucio account names to grant admin
                 status in OPA data.  These accounts will satisfy the
                 _is_privileged rule without being 'root'.
                 In production, generate this list from Rucio's account
                 attribute table and run this script on a schedule.

This script covers the Phase 2 TODO:
  "Ingest Rego policies into OPA via available interfaces covering the
   selected permission actions."

Selected permission actions (from Rucio generic.py) delegated to OPA:
  - add_rule, del_rule, update_rule, approve_rule
  - add_rse, update_rse, del_rse, add_rse_attribute, del_rse_attribute
  - add_did, add_dids, attach_dids, detach_dids
  - all other actions → privileged-only fallback in Rego
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

REGO_PATH = Path(__file__).parent.parent / "rego" / "authz.rego"
POLICY_ID = "authz"


def put(url: str, body: bytes, content_type: str) -> int:
    req = Request(url, data=body, headers={"Content-Type": content_type}, method="PUT")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status
    except URLError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def ingest_policy(base_url: str) -> None:
    rego_text = REGO_PATH.read_text()
    url = f"{base_url.rstrip('/')}/v1/policies/{POLICY_ID}"
    status = put(url, rego_text.encode(), "text/plain")
    print(f"Policy '{POLICY_ID}' ingested — HTTP {status}")


def ingest_admin_data(base_url: str, admins: list[str]) -> None:
    """
    Push the admin set as OPA data so Rego can resolve _is_privileged
    without trusting the Python caller's is_admin flag.

    Data path: /v1/data/vo/admins
    Rego usage (add to authz.rego when ready):
        _is_privileged if { data.vo.admins[input.issuer] }
    """
    admin_set = {account: True for account in admins}
    url = f"{base_url.rstrip('/')}/v1/data/vo"
    body = json.dumps({"admins": admin_set}).encode()
    status = put(url, body, "application/json")
    print(f"Admin data ingested ({len(admins)} accounts) — HTTP {status}")


def health_check(base_url: str) -> None:
    try:
        with urlopen(f"{base_url.rstrip('/')}/health", timeout=5) as resp:
            if resp.status != 200:
                print(f"ERROR: OPA health check returned HTTP {resp.status}", file=sys.stderr)
                sys.exit(1)
    except URLError as exc:
        print(f"ERROR: OPA not reachable at {base_url} — {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"OPA reachable at {base_url}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Rego policies into OPA")
    parser.add_argument("--opa-url", default="http://localhost:8181", help="OPA server base URL")
    parser.add_argument(
        "--admins",
        default="",
        help="Comma-separated Rucio account names to set as admins in OPA data",
    )
    args = parser.parse_args()

    base_url: str = args.opa_url
    admins: list[str] = [a.strip() for a in args.admins.split(",") if a.strip()]

    health_check(base_url)
    ingest_policy(base_url)
    if admins:
        ingest_admin_data(base_url, admins)
    else:
        print(
            "No --admins supplied; skipping admin data ingest. "
            "Only 'root' will be treated as privileged until data is loaded."
        )

    print("Done.")


if __name__ == "__main__":
    main()
