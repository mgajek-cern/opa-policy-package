#!/usr/bin/env python3
"""
ingest_policies.py — load Rego policy and data bundle into a running OPA server.

Phase 3 additions over Phase 2:
  - Ingests vo/policy data bundle (allowed_protocol_combos, known_rse_types,
    allowed_schemes) so Rego rules are data-driven rather than hardcoded.
  - Ingests vo/admins as before.

Usage:
    python ingest_policies.py [--opa-url URL] [--admins alice,bob]
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

REGO_PATH = Path(__file__).parent.parent / "rego" / "authz.rego"
POLICY_ID = "authz_v2"

# ---------------------------------------------------------------------------
# Default policy data — operators override via OPA bundle or re-ingestion
# ---------------------------------------------------------------------------

DEFAULT_POLICY_DATA = {
    "allowed_protocol_combos": [
        ["webdav", "webdav"],
        ["s3", "webdav"],
        ["xrdhttp", "webdav"],
        ["s3", "xrdhttp"],
        ["xrdhttp", "xrdhttp"],
    ],
    "known_rse_types": [
        "DATADISK",
        "SCRATCHDISK",
        "LOCALGROUPDISK",
        "TAPE",
        "USERDISK",
    ],
    "allowed_schemes": [
        "davs",
        "s3",
        "https",
        "root",
        "xrdhttp",
        "gsiftp",
    ],
}


def put(url: str, body: bytes, content_type: str) -> int:
    req = Request(url, data=body, headers={"Content-Type": content_type}, method="PUT")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status
    except URLError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


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


def ingest_policy(base_url: str) -> None:
    rego_text = REGO_PATH.read_text()
    url = f"{base_url.rstrip('/')}/v1/policies/{POLICY_ID}"
    status = put(url, rego_text.encode(), "text/plain")
    print(f"Policy '{POLICY_ID}' ingested — HTTP {status}")


def ingest_policy_data(base_url: str) -> None:
    """Push data-driven policy configuration (combos, RSE types, schemes)."""
    url = f"{base_url.rstrip('/')}/v1/data/vo/policy"
    body = json.dumps(DEFAULT_POLICY_DATA).encode()
    status = put(url, body, "application/json")
    print(f"Policy data bundle ingested — HTTP {status}")


def ingest_admin_data(base_url: str, admins: list[str]) -> None:
    admin_set = {account: True for account in admins}
    url = f"{base_url.rstrip('/')}/v1/data/vo"
    body = json.dumps({"admins": admin_set}).encode()
    status = put(url, body, "application/json")
    print(f"Admin data ingested ({len(admins)} accounts) — HTTP {status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Phase 3 Rego policy into OPA")
    parser.add_argument("--opa-url", default="http://localhost:8181")
    parser.add_argument("--admins", default="")
    args = parser.parse_args()

    base_url: str = args.opa_url
    admins: list[str] = [a.strip() for a in args.admins.split(",") if a.strip()]

    health_check(base_url)
    ingest_policy(base_url)
    ingest_policy_data(base_url)

    if admins:
        ingest_admin_data(base_url, admins)
    else:
        print("No --admins supplied — only 'root' and is_admin=true accounts will be privileged.")

    print("Done.")


if __name__ == "__main__":
    main()
