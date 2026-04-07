"""Shared pytest fixtures — no Rucio DB required."""

import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Minimal Rucio stubs so the policy packages import without a running Rucio
# ---------------------------------------------------------------------------


def _make_stub_modules() -> None:
    """Insert lightweight stubs for rucio modules used by the packages."""
    # rucio top-level
    rucio_mod = types.ModuleType("rucio")
    sys.modules.setdefault("rucio", rucio_mod)

    # rucio.core.account
    account_mod = types.ModuleType("rucio.core.account")
    account_mod.has_account_attribute = lambda account, key, session=None: False  # type: ignore[attr-defined]
    sys.modules["rucio.core"] = types.ModuleType("rucio.core")
    sys.modules["rucio.core.account"] = account_mod

    # rucio.common.types  (just needs InternalAccount)
    common_mod = types.ModuleType("rucio.common")
    types_mod = types.ModuleType("rucio.common.types")

    class _InternalAccount:
        def __init__(self, external: str):
            self.external = external

        def __eq__(self, other):
            if isinstance(other, _InternalAccount):
                return self.external == other.external
            return self.external == other

        def __repr__(self):
            return f"InternalAccount({self.external!r})"

    types_mod.InternalAccount = _InternalAccount  # type: ignore[attr-defined]
    sys.modules["rucio.common"] = common_mod
    sys.modules["rucio.common.types"] = types_mod


_make_stub_modules()

# Make phase1 src importable
sys.path.insert(
    0, str(__import__("pathlib").Path(__file__).parent.parent / "phase1-no-opa" / "src")
)
# Make phase2 src importable
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "phase2-opa" / "src"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_account():
    """Factory that produces a minimal InternalAccount-like object."""
    from rucio.common.types import InternalAccount

    def _factory(name: str) -> InternalAccount:
        return InternalAccount(name)

    return _factory


@pytest.fixture()
def root(make_account):
    return make_account("root")


@pytest.fixture()
def admin_account(make_account, monkeypatch):
    """An account that has the 'admin' attribute set."""
    import rucio.core.account as ra

    import rucio_no_opa_policy.permission as p1_perm

    account = make_account("adminuser")
    # Patch in both the rucio module and the phase1 permission module's import
    monkeypatch.setattr(ra, "has_account_attribute", lambda **kw: True)
    monkeypatch.setattr(p1_perm, "_is_admin", lambda issuer, *, session=None: True)
    return account


@pytest.fixture()
def regular_account(make_account):
    return make_account("alice")
