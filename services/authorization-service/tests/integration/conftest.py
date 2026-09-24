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
from contextlib import suppress
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_for_logs

SERVICE_ROOT = Path(__file__).resolve().parents[2]  # services/authorization-service
REGO_PATH = SERVICE_ROOT / "docker" / "authz.rego"
INGEST_SCRIPT = SERVICE_ROOT / "scripts" / "ingest_policies.py"
REALM_JSON = SERVICE_ROOT / "docker" / "realm.json"
COMPOSE_FILE = SERVICE_ROOT / "docker" / "docker-compose.yml"
OPA_IMAGE = "openpolicyagent/opa:1.8.0"
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:23.0.1"


def _put(url: str, body: bytes, content_type: str) -> None:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": content_type}, method="PUT"
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status in (200, 204), f"PUT {url} returned {response.status}"


def _phase_data() -> dict[str, dict[str, Any]]:
    """The service's phase 7 data bundle, read from the ingest script.

    Importing it keeps one source for policy data, so the tests cannot drift
    from what the testbed loads.
    """
    spec = importlib.util.spec_from_file_location("ingest_policies", INGEST_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(module.PHASE.data)


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
def keycloak() -> Iterator[tuple[str, DockerContainer]]:
    """A Keycloak container with the phase 7 realm imported — issuer for
    validated_claims (api/auth.py). Mirrors the `pdp` fixture's shape."""
    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_env("KEYCLOAK_ADMIN", "admin")
        .with_env("KEYCLOAK_ADMIN_PASSWORD", "admin")
        .with_env("KC_HTTP_ENABLED", "true")
        .with_env("KC_HOSTNAME_STRICT", "false")
        .with_command(
            "start-dev --features=token-exchange,admin-fine-grained-authz "
            "--import-realm --health-enabled=true"
        )
        .with_exposed_ports(8080)
        .with_volume_mapping(str(REALM_JSON), "/opt/keycloak/data/import/realm.json", mode="ro")
    )
    with container:
        wait_for_logs(container, "Keycloak.*started", timeout=90)
        host_ip = container.get_container_host_ip()
        port = container.get_exposed_port(8080)
        yield f"http://{host_ip}:{port}", container


def _kc(container: DockerContainer, *args: str) -> str:
    """Run kcadm.sh inside the Keycloak container via docker-py's
    exec_run (the API testcontainers wraps DockerContainer around),
    since DockerContainer itself doesn't expose .exec()."""
    exec_result = container.get_wrapped_container().exec_run(["/opt/keycloak/bin/kcadm.sh", *args])
    output = exec_result.output.decode().strip()
    assert exec_result.exit_code == 0, f"kcadm.sh {' '.join(args)} failed: {output}"
    return output


def _kc_client_uuid(container: DockerContainer, client_id: str) -> str:
    csv = _kc(
        container,
        "get",
        "clients",
        "-r",
        "rucio",
        "-q",
        f"clientId={client_id}",
        "--fields",
        "id",
        "--format",
        "csv",
        "--noquotes",
    )
    uuid = csv.strip()
    assert uuid, f"client '{client_id}' not found — is realm.json imported?"
    return uuid


def _grant_token_exchange(container: DockerContainer, requester: str, target: str) -> None:
    """Same three-step grant as scripts/test_token_exchange.sh's
    grant_token_exchange(): Keycloak 23's legacy token exchange needs
    this explicit Fine-Grained Admin Permission, it isn't implied by
    token.exchange.standard.flow.enabled alone."""
    _kc(
        container,
        "config",
        "credentials",
        "--server",
        "http://localhost:8080",
        "--realm",
        "master",
        "--user",
        "admin",
        "--password",
        "admin",
    )

    requester_uuid = _kc_client_uuid(container, requester)
    target_uuid = _kc_client_uuid(container, target)
    rm_uuid = _kc_client_uuid(container, "realm-management")

    _kc(
        container,
        "update",
        f"clients/{target_uuid}/management/permissions",
        "-r",
        "rucio",
        "-s",
        "enabled=true",
    )

    policy_name = f"exchange-to-{target}".replace(":", "_")
    requester_json = f'["{requester_uuid}"]'
    with suppress(AssertionError):
        _kc(
            container,
            "create",
            f"clients/{rm_uuid}/authz/resource-server/policy/client",
            "-r",
            "rucio",
            "-s",
            f"name={policy_name}",
            "-s",
            f"clients={requester_json}",
            "-s",
            "logic=POSITIVE",
        )

    policy_id = _kc(
        container,
        "get",
        f"clients/{rm_uuid}/authz/resource-server/policy?name={policy_name}",
        "-r",
        "rucio",
        "--fields",
        "id",
        "--format",
        "csv",
        "--noquotes",
    ).splitlines()[0]
    _kc(
        container,
        "update",
        f"clients/{rm_uuid}/authz/resource-server/policy/client/{policy_id}",
        "-r",
        "rucio",
        "-s",
        f"clients={requester_json}",
    )

    perm_name = f"token-exchange.permission.client.{target_uuid}"
    perm_id = _kc(
        container,
        "get",
        f"clients/{rm_uuid}/authz/resource-server/permission?name={perm_name}",
        "-r",
        "rucio",
        "--fields",
        "id",
        "--format",
        "csv",
        "--noquotes",
    ).splitlines()[0]
    _kc(
        container,
        "update",
        f"clients/{rm_uuid}/authz/resource-server/permission/scope/{perm_id}",
        "-r",
        "rucio",
        "-s",
        f'policies=["{policy_id}"]',
    )


@pytest.fixture(scope="session")
def _keycloak_token_exchange_granted(keycloak: tuple[str, DockerContainer]) -> None:
    """Runs grant_token_exchange exactly once per session. Both
    bearer_token and admin_bearer_token depend on this rather than
    calling _grant_token_exchange themselves — kcadm's `config
    credentials` step is not safe to invoke twice back-to-back (it
    re-authenticates against Keycloak's admin API and can stall/rate-
    limit on rapid repeat calls), which is what caused test collection
    to hang here previously."""
    _keycloak_url, container = keycloak
    _grant_token_exchange(container, requester="rucio", target="authz-service")


@pytest.fixture(scope="session")
def bearer_token(
    keycloak: tuple[str, DockerContainer],
    _keycloak_token_exchange_granted: None,
) -> str:
    """A real, exchanged bearer token (randomaccount, audience=authz-service,
    scope=pep:rucio) — same flow as scripts/test_token_exchange.sh's
    grant_token_exchange + mint + exchange, run once per session."""
    return _exchanged_token(keycloak, username="randomaccount", password="secret")


@pytest.fixture(scope="session")
def admin_bearer_token(
    keycloak: tuple[str, DockerContainer],
    _keycloak_token_exchange_granted: None,
) -> str:
    """Same flow as bearer_token, for adminuser — carries the
    rucio-admins/atlas-production entitlements, so this is what
    exercises _is_privileged's entitlement branch end-to-end now that
    subject_from() forwards real claims (see api/routes/_pdp.py)."""
    return _exchanged_token(keycloak, username="adminuser", password="admin123")


def _exchanged_token(keycloak: tuple[str, DockerContainer], *, username: str, password: str) -> str:
    keycloak_url, _container = keycloak

    token_url = f"{keycloak_url}/realms/rucio/protocol/openid-connect/token"
    with httpx.Client(timeout=15.0) as http:
        user_resp = http.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "rucio",
                "client_secret": "rucio-secret",
                "username": username,
                "password": password,
                "scope": "openid",
            },
        )
        user_resp.raise_for_status()
        user_token = user_resp.json()["access_token"]

        exchange_resp = http.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": "rucio",
                "client_secret": "rucio-secret",
                "subject_token": user_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "authz-service",
                "scope": "pep:rucio",
            },
        )
        exchange_resp.raise_for_status()
        return exchange_resp.json()["access_token"]


@pytest.fixture(scope="session")
def service(
    pdp: str, keycloak: tuple[str, DockerContainer], monkeypatch_session: pytest.MonkeyPatch
) -> Iterator[str]:
    """The app, run in-process by uvicorn on a free port."""
    keycloak_url, _container = keycloak
    monkeypatch_session.setenv("AUTHZ_PDP", "opa")
    monkeypatch_session.setenv("AUTHZ_OPA_URL", pdp)
    monkeypatch_session.setenv("AUTHZ_OPA_POLICY_PATH", "vo/authz/v6/allow")
    monkeypatch_session.setenv("AUTHZ_OIDC_ISSUER", f"{keycloak_url}/realms/rucio")
    monkeypatch_session.setenv("AUTHZ_OIDC_AUDIENCE", "authz-service")

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
