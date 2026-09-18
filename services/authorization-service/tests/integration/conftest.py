"""Container and app lifecycle for the integration suite.

The fixtures own every container through testcontainers: no compose file and
no shared testbed (design-006, "Testing"). Docker is required.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_for_logs

REPO_ROOT = Path(__file__).resolve().parents[4]
REGO_PATH = REPO_ROOT / "policies" / "rego" / "phase7" / "authz.rego"
INGEST_SCRIPT = REPO_ROOT / "scripts" / "ingest_policies.py"
PHASE = "phase7"
OPA_IMAGE = "openpolicyagent/opa:1.8.0"


def _put(url: str, body: bytes, content_type: str) -> None:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": content_type}, method="PUT"
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status in (200, 204), f"PUT {url} returned {response.status}"


def _phase_data() -> dict[str, dict[str, Any]]:
    """The phase's data bundle, read from the ingest script.

    Importing it keeps one source for policy data, so the tests cannot drift
    from what the testbed loads.
    """
    spec = importlib.util.spec_from_file_location("ingest_policies", INGEST_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(module.PHASES[PHASE].data)


def _wait_for_health(base_url: str, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.2)
    raise TimeoutError(f"{base_url} never became healthy")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


@pytest.fixture(scope="session")
def pdp() -> Iterator[str]:
    """An OPA container with the phase 7 policy and data loaded."""
    container = (
        DockerContainer(OPA_IMAGE)
        .with_command("run --server --addr=0.0.0.0:8181")
        .with_exposed_ports(8181)
    )
    with container:
        wait_for_logs(container, "Initializing server", timeout=60)
        base_url = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8181)}"
        _wait_for_health(base_url)

        _put(f"{base_url}/v1/policies/authz_v6", REGO_PATH.read_bytes(), "text/plain")
        for path, payload in _phase_data().items():
            _put(f"{base_url}/v1/data/{path}", json.dumps(payload).encode(), "application/json")

        yield base_url


@pytest.fixture(scope="session")
def service(pdp: str, monkeypatch_session: pytest.MonkeyPatch) -> Iterator[str]:
    """The app, run in-process by uvicorn on a free port."""
    monkeypatch_session.setenv("AUTHZ_PDP", "opa")
    monkeypatch_session.setenv("AUTHZ_OPA_URL", pdp)
    monkeypatch_session.setenv("AUTHZ_OPA_POLICY_PATH", "vo/authz/v6/allow")

    from authz_service.main import create_app

    port = _free_port()
    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise TimeoutError("the service never started")

    yield base_url

    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture(scope="session")
def monkeypatch_session() -> Iterator[pytest.MonkeyPatch]:
    patcher = pytest.MonkeyPatch()
    yield patcher
    patcher.undo()


@pytest.fixture
def client(service: str) -> Iterator[httpx.Client]:
    """Plain HTTP for now; the generated transport replaces it with the first
    operation."""
    with httpx.Client(base_url=service, timeout=5.0) as http_client:
        yield http_client
