"""Invariant 3, for the one case import-linter cannot express.

It rejects subpackages of external packages, so the ban on the OTel SDK in
the core is checked here instead. The rest of the dependency direction is an
import-linter contract (design-006, "Conformance checks").
"""

from __future__ import annotations

import ast
from pathlib import Path

CORE = Path(__file__).resolve().parents[2] / "src" / "authz_service" / "core"
FORBIDDEN_PREFIXES = ("opentelemetry.sdk", "opentelemetry.exporter")


def _imported_modules(source: Path) -> set[str]:
    tree = ast.parse(source.read_text())
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def test_core_does_not_import_the_otel_sdk() -> None:
    offenders = {
        f"{path.name}: {module}"
        for path in CORE.rglob("*.py")
        for module in _imported_modules(path)
        if module.startswith(FORBIDDEN_PREFIXES)
    }
    assert not offenders, f"core may use the OTel API, not the SDK: {sorted(offenders)}"


def test_core_modules_exist() -> None:
    assert {path.name for path in CORE.glob("*.py")} >= {"model.py", "ports.py"}
