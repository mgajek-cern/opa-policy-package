#!/usr/bin/env python3
"""
ingest_policies.py — load a phase's Rego policy and data bundles into a running OPA server.

Usage:
    python ingest_policies.py --phase phase6 [--opa-url URL] [--admins alice,bob]

Each phase ingests its Rego under a distinct policy ID, so several phases can
coexist on one OPA instance. Data bundles differ by phase:

    phase2  admins only (vo/admins)
    phase3  + data-driven RSE types (vo/policy)
    phase4  + wlcg.groups -> privilege (vo/group_policy)
    phase5  + URN entitlements -> privilege (vo/entitlement_policy)
    phase6  + RSE-name allowlist for the transfer testbed

Re-run at any time to update a live OPA without restarting Rucio.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

# Repo root is the script's grandparent: <root>/scripts/ingest_policies.py
REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_RSE_TYPES = [
    "DATADISK",
    "SCRATCHDISK",
    "LOCALGROUPDISK",
    "TAPE",
    "USERDISK",
]

# wlcg.groups paths -> privilege level (phase 4).
GROUP_POLICY = {
    "/rucio/admins": "admin",
    "/atlas/production": "admin",
    "/rucio/users": "user",
    "/atlas/users": "user",
}

# URN entitlement strings -> privilege level (phases 5, 6).
ENTITLEMENT_POLICY = {
    "urn:example:aai.example.org:group:rucio-admins:role=member": "admin",
    "urn:example:aai.example.org:group:atlas-production:role=member": "admin",
    "urn:example:aai.example.org:group:rucio-users:role=member": "user",
    "urn:example:aai.example.org:group:atlas-users:role=member": "user",
}


@dataclass(frozen=True)
class PhaseSpec:
    """What a single phase ingests.

    policy_id:  OPA policy ID the Rego is stored under.
    data:       data path (relative to /v1/data/) -> JSON payload.
    supports_admins: whether --admins is meaningful; phases 4+ resolve
                privilege from token claims instead of an account list.
    """

    policy_id: str
    data: dict[str, dict] = field(default_factory=dict)
    supports_admins: bool = False


PHASES: dict[str, PhaseSpec] = {
    "phase2": PhaseSpec(
        policy_id="authz",
        supports_admins=True,
    ),
    "phase3": PhaseSpec(
        policy_id="authz_v2",
        data={"vo/policy": {"known_rse_types": DEFAULT_RSE_TYPES}},
        supports_admins=True,
    ),
    "phase4": PhaseSpec(
        policy_id="authz_v3",
        data={
            "vo/policy": {"known_rse_types": DEFAULT_RSE_TYPES},
            "vo/group_policy": GROUP_POLICY,
        },
    ),
    "phase5": PhaseSpec(
        policy_id="authz_v4",
        data={
            "vo/policy": {"known_rse_types": DEFAULT_RSE_TYPES},
            "vo/entitlement_policy": ENTITLEMENT_POLICY,
        },
    ),
    "phase6": PhaseSpec(
        policy_id="authz_v5",
        data={
            "vo/policy": {
                "known_rse_types": DEFAULT_RSE_TYPES,
                # XRD3/XRD4/TEAPOT1/TEAPOT2 don't follow the NAME_TYPE
                # convention; allowlisted rather than relaxing it globally.
                "allowlisted_rse_names": ["XRD3", "XRD4", "TEAPOT1", "TEAPOT2"],
            },
            "vo/entitlement_policy": ENTITLEMENT_POLICY,
        },
    ),
}


def put(url: str, body: bytes, content_type: str) -> int:
    req = Request(url, data=body, headers={"Content-Type": content_type}, method="PUT")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status
    except URLError as exc:
        print(f"ERROR: PUT {url} failed — {exc}", file=sys.stderr)
        sys.exit(1)


def health_check(base_url: str) -> None:
    try:
        with urlopen(f"{base_url}/health", timeout=5) as resp:
            if resp.status != 200:
                print(f"ERROR: OPA health check returned HTTP {resp.status}", file=sys.stderr)
                sys.exit(1)
    except URLError as exc:
        print(f"ERROR: OPA not reachable at {base_url} — {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"OPA reachable at {base_url}")


def ingest_policy(base_url: str, spec: PhaseSpec, rego_path: Path) -> None:
    if not rego_path.is_file():
        print(f"ERROR: Rego file not found: {rego_path}", file=sys.stderr)
        sys.exit(1)
    status = put(
        f"{base_url}/v1/policies/{spec.policy_id}",
        rego_path.read_text().encode(),
        "text/plain",
    )
    print(f"Policy '{spec.policy_id}' ingested from {rego_path} — HTTP {status}")


def ingest_data(base_url: str, spec: PhaseSpec) -> None:
    for path, payload in spec.data.items():
        status = put(
            f"{base_url}/v1/data/{path}",
            json.dumps(payload).encode(),
            "application/json",
        )
        print(f"Data '{path}' ingested ({len(payload)} key(s)) — HTTP {status}")


def ingest_admins(base_url: str, admins: list[str]) -> None:
    """Push the admin set so Rego resolves _is_privileged from OPA data
    rather than trusting an is_admin flag from the Python caller."""
    body = json.dumps({"admins": {account: True for account in admins}}).encode()
    status = put(f"{base_url}/v1/data/vo", body, "application/json")
    print(f"Admin data ingested ({len(admins)} account(s)) — HTTP {status}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--phase",
        required=True,
        choices=sorted(PHASES),
        help="which phase's policy to ingest",
    )
    parser.add_argument(
        "--opa-url",
        default="http://localhost:8181",
        help="OPA server base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--rego-path",
        type=Path,
        default=None,
        help="override the Rego file (default: <repo>/rego/<phase>/authz.rego)",
    )
    parser.add_argument(
        "--admins",
        default="",
        help="comma-separated Rucio accounts to mark admin (phases 2-3 only)",
    )
    args = parser.parse_args()

    spec = PHASES[args.phase]
    base_url = args.opa_url.rstrip("/")
    rego_path = args.rego_path or REPO_ROOT / "rego" / args.phase / "authz.rego"
    admins = [a.strip() for a in args.admins.split(",") if a.strip()]

    health_check(base_url)
    ingest_policy(base_url, spec, rego_path)
    ingest_data(base_url, spec)

    if admins and not spec.supports_admins:
        print(
            f"WARNING: --admins ignored for {args.phase}; privilege is resolved "
            "from token claims via the policy data above.",
            file=sys.stderr,
        )
    elif admins:
        ingest_admins(base_url, admins)
    elif spec.supports_admins:
        print(
            "No --admins supplied; skipping admin data. Only 'root' will be "
            "privileged until it is loaded."
        )

    print("Done.")


if __name__ == "__main__":
    main()
