"""The one check import-linter can't express: core must not import the
OTel SDK specifically, as opposed to the OTel API (design-006, "The PDP
port" / ADR-004 invariant 3). import-linter's forbidden contract can
target the top-level opentelemetry package but not one of its
submodules, so this stays a plain AST check. Everything else about
invariant 3 — core has no upward dependency on api/adapters, and no
direct fastapi/pydantic/httpx import — is enforced by .importlinter
instead (see `make lint`, which runs lint-imports).
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
