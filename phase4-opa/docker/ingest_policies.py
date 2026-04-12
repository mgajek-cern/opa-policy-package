#!/usr/bin/env python3
"""
ingest_policies.py — Phase 4: load Rego policy + data bundle + group policy into OPA.

Additions over Phase 3:
  - Ingests vo/group_policy: maps wlcg.groups paths → privilege levels.
    This replaces is_root/is_admin flags with token-native group evaluation.
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

REGO_PATH = Path(__file__).parent.parent / "rego" / "authz.rego"
POLICY_ID = "authz_v3"

DEFAULT_POLICY_DATA = {
    "allowed_protocol_combos": [
        ["webdav", "webdav"],
        ["s3", "webdav"],
        ["xrdhttp", "webdav"],
        ["s3", "xrdhttp"],
        ["xrdhttp", "xrdhttp"],
    ],
    "known_rse_types": ["DATADISK", "SCRATCHDISK", "LOCALGROUPDISK", "TAPE", "USERDISK"],
    "allowed_schemes": ["davs", "s3", "https", "root", "xrdhttp", "gsiftp"],
}

# Maps wlcg.groups paths → privilege level.
# Update at runtime via re-ingestion — no Rucio restart needed.
DEFAULT_GROUP_POLICY = {
    "/rucio/admins": "admin",
    "/atlas/production": "admin",
    "/rucio/users": "user",
    "/atlas/users": "user",
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
                sys.exit(1)
    except URLError as exc:
        print(f"ERROR: OPA not reachable — {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"OPA reachable at {base_url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa-url", default="http://localhost:8181")
    args = parser.parse_args()
    base = args.opa_url

    health_check(base)

    status = put(f"{base}/v1/policies/{POLICY_ID}", REGO_PATH.read_text().encode(), "text/plain")
    print(f"Policy '{POLICY_ID}' ingested — HTTP {status}")

    status = put(
        f"{base}/v1/data/vo/policy", json.dumps(DEFAULT_POLICY_DATA).encode(), "application/json"
    )
    print(f"Policy data bundle ingested — HTTP {status}")

    status = put(
        f"{base}/v1/data/vo/group_policy",
        json.dumps(DEFAULT_GROUP_POLICY).encode(),
        "application/json",
    )
    print(f"Group policy ingested ({len(DEFAULT_GROUP_POLICY)} groups) — HTTP {status}")

    print("Done.")


if __name__ == "__main__":
    main()
