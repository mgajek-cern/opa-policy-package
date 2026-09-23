#!/usr/bin/env python3
"""Post-generation patches for phase7-opa's rucio_authz_client.

python-legacy v6.6.0 (compatibleWithPythonLegacy=true) has a template
bug: string-enum allowed_values render bare unquoted identifiers
instead of string literals, causing NameError at runtime whenever the
field is actually set. Confirmed on three fields; re-run
`grep -rn "allowed_values = \\[" .../models/` after regenerating if the
spec grows more string enums, and add any new broken lines here.

Usage: patch_phase7_client.py <rucio_authz_client_dir>
"""

import sys
from pathlib import Path

PATCHES = [
    (
        "models/subject.py",
        "allowed_values = [None,rucio_account, oidc_subject]",
        'allowed_values = [None, "rucio_account", "oidc_subject"]',
    ),
    ("models/health_status.py", "allowed_values = [None,ok]", 'allowed_values = [None, "ok"]'),
    (
        "models/did.py",
        "allowed_values = [None,file, dataset, container]",
        'allowed_values = [None, "file", "dataset", "container"]',
    ),
]


def main():
    root = Path(sys.argv[1])
    for rel_path, old, new in PATCHES:
        path = root / rel_path
        text = path.read_text()
        if old not in text:
            print(
                f"WARNING: expected pattern not found in {rel_path} — "
                f"generator output may have changed; check manually",
                file=sys.stderr,
            )
            continue
        path.write_text(text.replace(old, new))
        print(f"patched {rel_path}")


if __name__ == "__main__":
    main()
