import json
import os
import shutil
import signal
import subprocess
import sys
import types
from socket import socket
from time import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

RUCIO_ACCOUNT = "root"
RUCIO_USERNAME = "ddmlab"
RUCIO_PASSWORD = "secret"

OPA_STARTUP_TIMEOUT = 10  # seconds


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

# Fixtures


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


def rucio_call(rucio_url: str, path: str, token: str, method: str = "GET", json_body=None):
    """Return (status_code, response_bytes) for an authenticated Rucio API call."""
    data = json.dumps(json_body).encode() if json_body is not None else None
    headers = {"X-Rucio-Auth-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(f"{rucio_url}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def rucio_opa_container_logs():
    """Return combined stdout+stderr of `docker logs rucio-opa`, or None if unavailable.

    OPA writes its structured access log to stderr, not stdout — both
    streams are checked. Returns None (rather than raising) when Docker
    isn't installed or the container isn't running, so callers can skip
    cleanly instead of failing on an environment precondition.
    """
    docker_path = shutil.which("docker")
    if not docker_path:
        return None
    result = subprocess.run(
        [docker_path, "logs", "rucio-opa"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return None
    return result.stdout + result.stderr


@pytest.fixture(scope="module")
def stack_urls():
    """Resolve and verify the Rucio + OPA stack is reachable, else skip the module.

    Phase 4 needs a Keycloak URL too — it defines its own stack_urls fixture
    locally (in test_phase4_smoke.py) which shadows this one for that module
    rather than forcing a Keycloak-shaped 3-tuple onto Phase 2/3.
    """
    rucio_url = os.environ.get("RUCIO_URL", "http://localhost").rstrip("/")
    opa_url = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")

    try:
        urlopen(f"{opa_url}/health", timeout=3)
    except URLError as exc:
        pytest.skip(f"OPA not reachable at {opa_url}: {exc}")

    try:
        with urlopen(f"{rucio_url}/ping", timeout=3) as resp:
            body = json.loads(resp.read())
        assert "version" in body
    except (URLError, AssertionError) as exc:
        pytest.skip(f"Rucio not reachable at {rucio_url}: {exc}")

    return rucio_url, opa_url


@pytest.fixture(scope="module")
def root_token(stack_urls):
    rucio_url, _ = stack_urls
    req = Request(
        f"{rucio_url}/auth/userpass",
        headers={
            "X-Rucio-Account": RUCIO_ACCOUNT,
            "X-Rucio-Username": RUCIO_USERNAME,
            "X-Rucio-Password": RUCIO_PASSWORD,
        },
    )
    with urlopen(req, timeout=10) as resp:
        token = resp.headers.get("X-Rucio-Auth-Token")
    assert token, "Expected X-Rucio-Auth-Token header in auth response"
    return token


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_opa(port: int, timeout: float = OPA_STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def build_opa_server_fixture(rego_path, default_policy_path):
    """Return a pytest fixture that spawns/reuses OPA for this phase's Rego."""

    @pytest.fixture(scope="module")
    def opa_server():
        external_url = os.environ.get("OPA_URL", "").strip()
        if external_url:
            try:
                urlopen(f"{external_url.rstrip('/')}/health", timeout=3)
            except Exception as exc:
                pytest.skip(f"OPA_URL={external_url} is not reachable: {exc}")
            yield external_url
            return

        opa_path = shutil.which("opa")
        if not opa_path:
            pytest.skip("'opa' binary not found on PATH and OPA_URL is not set.")

        port = _free_port()
        proc = subprocess.Popen(
            [
                opa_path,
                "run",
                "--server",
                "--log-level",
                "error",
                f"--addr=127.0.0.1:{port}",
                str(rego_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _wait_for_opa(port):
            proc.terminate()
            pytest.skip(f"OPA did not start on port {port}")
        yield f"http://127.0.0.1:{port}"
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)

    return opa_server
