"""
Plain helpers shared by the test modules.

Fixtures live in conftest.py; everything here is an ordinary constant or
function, imported explicitly (`from helpers import ...`). pytest's default
"prepend" import mode puts this directory on sys.path, so the import works on
the host (phases 4/5) and inside the rucio-client container (phase 6), where
the directory is mounted at /tests.

Rucio REST and token requests go through a small urllib layer rather than
requests: the phase 4/5 suites run on the host, where requests may not be
installed. requests is only needed by the WebDAV helpers, which run in the
container.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import ssl
import time
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from email.message import Message

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # host runs of phases 4/5 never reach the WebDAV helpers
    requests = None

log = logging.getLogger("helpers")


# ── Configuration ─────────────────────────────────────────────────────────

RUCIO_ACCOUNT = "root"
RUCIO_USERNAME = "ddmlab"
RUCIO_PASSWORD = "secret"

# Host runs (phases 4/5) get RUCIO_URL from the Makefile; the container
# default is the in-network service name.
RUCIO_REST_URL = (os.environ.get("RUCIO_URL") or "http://rucio-server").rstrip("/")

# Which credential the transfer suite uses. 'userpass' authenticates as root,
# which the Rego short-circuits before any entitlement lookup — fine for
# testing transfers, but it does not exercise the claims path.
RUCIO_AUTH = os.environ.get("RUCIO_AUTH", "userpass")

OIDC_ISSUER = os.environ.get("OIDC_ISSUER") or "https://keycloak:8443/realms/rucio"
KEYCLOAK_URL = (os.environ.get("KEYCLOAK_URL") or "").rstrip("/")

# Precedence: an explicit token URL, then KEYCLOAK_URL (what the Makefile
# exports for host runs), then the in-network issuer.
OIDC_TOKEN_URL = os.environ.get("OIDC_TOKEN_URL") or (
    f"{KEYCLOAK_URL}/realms/rucio/protocol/openid-connect/token"
    if KEYCLOAK_URL
    else f"{OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/token"
)

OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID") or "rucio"
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET") or "rucio-secret"
OIDC_USERNAME = os.environ.get("OIDC_USERNAME") or "seeduser"
OIDC_PASSWORD = os.environ.get("OIDC_PASSWORD") or "secret"
OIDC_GRANT_TYPE = os.environ.get("OIDC_GRANT_TYPE") or "password"  # password | client_credentials
OIDC_EXPECTED_SCOPE = (
    os.environ.get("OIDC_EXPECTED_SCOPE") or "openid storage.read:/ storage.modify:/"
)
OIDC_TEAPOT_AUD_SCOPE = os.environ.get("OIDC_TEAPOT_AUD_SCOPE") or "aud:teapot1 aud:teapot2"

# RFC 8707 resource indicators require a URI. Only consulted under
# client_credentials (the LS AAI/EGI path).
OIDC_RESOURCE_SUFFIX = os.environ.get("OIDC_RESOURCE_SUFFIX") or ".example.org"

# Superset of the server's [oidc] expected_scope plus aud:rucio. A module can
# declare its own AUTHZ_SCOPE; OIDC_AUTHZ_SCOPE overrides both.
DEFAULT_AUTHZ_SCOPE = "openid offline_access storage.read:/ storage.modify:/ aud:rucio"

# Realm users. Must match AUTHZ_TEST_USERS in the phase's init script.
ADMIN_USERNAME = os.environ.get("OIDC_ADMIN_USERNAME", "adminuser")
ADMIN_PASSWORD = os.environ.get("OIDC_ADMIN_PASSWORD", "admin123")
USER_USERNAME = os.environ.get("OIDC_USER_USERNAME", "randomaccount")
USER_PASSWORD = os.environ.get("OIDC_USER_PASSWORD", "secret")
DEP_OPERATOR_USERNAME = os.environ.get("OIDC_DEP_OPERATOR_USERNAME", "depoperator")
DEP_OPERATOR_PASSWORD = os.environ.get("OIDC_DEP_OPERATOR_PASSWORD", "secret")
DEP_END_USER_USERNAME = os.environ.get("OIDC_DEP_END_USER_USERNAME", "dependuser")
DEP_END_USER_PASSWORD = os.environ.get("OIDC_DEP_END_USER_PASSWORD", "secret")
MODEL_DEVELOPER_USERNAME = os.environ.get("OIDC_MODEL_DEVELOPER_USERNAME", "modeldeveloper")
MODEL_DEVELOPER_PASSWORD = os.environ.get("OIDC_MODEL_DEVELOPER_PASSWORD", "secret")

MFA = "https://refeds.org/profile/mfa"
RULE_ID = "1f0e3dad99908345f7439f8ffabdffc4"

VALSTORAGE_HOST = os.environ.get("VALIDATION_STORAGE_HOST")
TEAPOT1_URL = os.environ.get("TEAPOT1_URL") or (
    f"https://{VALSTORAGE_HOST}:8081" if VALSTORAGE_HOST else "https://teapot1:8081"
)
TEAPOT2_URL = os.environ.get("TEAPOT2_URL") or (
    f"https://{VALSTORAGE_HOST}:8082" if VALSTORAGE_HOST else "https://teapot2:8081"
)


# ── HTTP ──────────────────────────────────────────────────────────────────

# The testbed's Keycloak and storage endpoints present certs signed by the
# testbed CA; verification is out of scope for these suites.
_UNVERIFIED_TLS = ssl.create_default_context()
_UNVERIFIED_TLS.check_hostname = False
_UNVERIFIED_TLS.verify_mode = ssl.CERT_NONE


@dataclass
class Reply:
    """The subset of requests.Response the tests rely on, over urllib."""

    status_code: int
    headers: Message
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode(errors="replace")

    def json(self):
        return json.loads(self.content)


def http(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    json_body=None,
    form: dict | None = None,
    auth: tuple | None = None,
    timeout: float = 30,
) -> Reply:
    """One HTTP request. Error statuses come back as a Reply, not an exception."""
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        # doseq: a list value becomes repeated fields — how RFC 8707
        # expresses several resource= audiences in one request.
        data = urlencode(form, doseq=True).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if auth is not None:
        hdrs["Authorization"] = (
            "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        )

    req = Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=timeout, context=_UNVERIFIED_TLS) as resp:
            return Reply(resp.status, resp.headers, resp.read())
    except HTTPError as exc:
        return Reply(exc.code, exc.headers, exc.read())


# ── Rucio REST ────────────────────────────────────────────────────────────
#
# REST rather than the Rucio Python client: the client needs a rucio.cfg, and
# auth_type=oidc there drives an interactive flow. REST also surfaces
# ExceptionClass, which is what distinguishes a policy deny (AccessDenied)
# from a rejected token (CannotAuthenticate) — both come back as 401.


def rucio_rest(path: str, token: str, method: str = "GET", body=None, timeout: float = 30) -> Reply:
    """Authenticated Rucio REST call with a raw bearer token."""
    return http(
        method,
        f"{RUCIO_REST_URL}{path}",
        headers={"X-Rucio-Auth-Token": token},
        json_body=body,
        timeout=timeout,
    )


def deny_reason(resp: Reply):
    """(ExceptionClass, ExceptionMessage) from a Rucio error response."""
    return resp.headers.get("ExceptionClass"), resp.headers.get("ExceptionMessage")


def expect(resp: Reply, ok, what: str) -> Reply:
    """Assert a REST call succeeded, reporting Rucio's exception headers."""
    assert resp.status_code in ok, (
        f"{what}: HTTP {resp.status_code} {deny_reason(resp)} {resp.text[:200]}"
    )
    return resp


def unique(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1000)}"


def stack_unreachable() -> str | None:
    """Why the Rucio stack can't be used, or None when it can."""
    try:
        ping = http("GET", f"{RUCIO_REST_URL}/ping", timeout=3)
        if ping.status_code != 200 or "version" not in ping.json():
            return f"Rucio at {RUCIO_REST_URL} answered /ping with HTTP {ping.status_code}"
    except (URLError, OSError, ValueError) as exc:
        return f"Rucio not reachable at {RUCIO_REST_URL}: {exc}"

    if KEYCLOAK_URL:
        try:
            health = http("GET", f"{KEYCLOAK_URL}/health/ready", timeout=3)
            if health.status_code != 200:
                return f"Keycloak at {KEYCLOAK_URL} not ready: HTTP {health.status_code}"
        except (URLError, OSError) as exc:
            return f"Keycloak not reachable at {KEYCLOAK_URL}: {exc}"
    return None


def userpass_token() -> str:
    resp = http(
        "GET",
        f"{RUCIO_REST_URL}/auth/userpass",
        headers={
            "X-Rucio-Account": RUCIO_ACCOUNT,
            "X-Rucio-Username": RUCIO_USERNAME,
            "X-Rucio-Password": RUCIO_PASSWORD,
        },
    )
    expect(resp, (200,), "userpass auth")
    token = resp.headers.get("X-Rucio-Auth-Token")
    assert token, "No X-Rucio-Auth-Token in /auth/userpass response"
    return token


# ── OIDC tokens ───────────────────────────────────────────────────────────


def _token_request(form: dict) -> str:
    resp = http(
        "POST",
        OIDC_TOKEN_URL,
        form=form,
        auth=(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET),
        timeout=10,
    )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"token request to {OIDC_TOKEN_URL} failed: HTTP {resp.status_code} {resp.text[:300]}"
        )
    return resp.json()["access_token"]


def password_token(username: str, password: str, scope: str = "openid") -> str:
    return _token_request(
        {"grant_type": "password", "username": username, "password": password, "scope": scope}
    )


def client_credentials_token(scope: str = "openid", resource=None) -> str:
    form = {"grant_type": "client_credentials", "scope": scope}
    if resource:
        # RFC 8707: resource stamps the aud claim; audience= does not.
        form["resource"] = resource
    return _token_request(form)


def rse_resource(name: str) -> str:
    """Map a bare RSE name to the URI form LS AAI/EGI expects as resource=."""
    if OIDC_GRANT_TYPE != "client_credentials":
        return name
    return f"https://{name}{OIDC_RESOURCE_SUFFIX}/"


def mint(scope: str, resource=None) -> str:
    """A storage token for the configured grant type."""
    if OIDC_GRANT_TYPE == "client_credentials":
        return client_credentials_token(scope=scope, resource=resource)
    return password_token(OIDC_USERNAME, OIDC_PASSWORD, scope=scope)


# ── OPA data documents and process ────────────────────────────────────────


def opa_get(opa_url: str, path: str):
    """Current value, or None when the path holds nothing.

    OPA answers 200 with no `result` key for an undefined path rather than
    404, so the absent case comes out of the .get() not the status.
    """
    resp = http("GET", f"{opa_url.rstrip('/')}/v1/data/{path}", timeout=5)
    if resp.status_code == 404:
        return None
    assert resp.status_code == 200, f"GET {path}: HTTP {resp.status_code} {resp.text[:200]}"
    return resp.json().get("result")


def opa_put(opa_url: str, path: str, data) -> None:
    resp = http("PUT", f"{opa_url.rstrip('/')}/v1/data/{path}", json_body=data, timeout=5)
    assert resp.status_code in (200, 204), f"PUT {path}: HTTP {resp.status_code}"


def opa_delete(opa_url: str, path: str) -> None:
    """Remove a data document. Tolerates it never having been written."""
    resp = http("DELETE", f"{opa_url.rstrip('/')}/v1/data/{path}", timeout=5)
    assert resp.status_code in (200, 204, 404), f"DELETE {path}: HTTP {resp.status_code}"


def opa_healthy(opa_url: str) -> bool:
    try:
        return http("GET", f"{opa_url.rstrip('/')}/health", timeout=3).status_code == 200
    except (URLError, OSError):
        return False


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ── Rucio transfer helpers ────────────────────────────────────────────────


def compute_pfn(
    token: str, rse: str, scope: str, name: str, scheme: str = "davs", operation: str = "write"
) -> str:
    """Resolve the PFN for a DID on an RSE via the server's own lfn2pfn."""
    resp = rucio_rest(
        f"/rses/{rse}/lfns2pfns?lfn={scope}:{name}&scheme={scheme}&operation={operation}",
        token,
    )
    expect(resp, (200,), f"lfns2pfns {rse} {scope}:{name}")
    data = resp.json()
    # Server returns {"scope:name": "pfn"}; tolerate a bare list.
    return next(iter(data.values())) if isinstance(data, dict) else data[0]


def register_replicas(token: str, rse: str, files: list) -> None:
    """Register one or more replicas. 409 means a prior run already did."""
    resp = rucio_rest("/replicas", token, "POST", {"rse": rse, "files": files})
    if resp.status_code == 409:
        log.warning("  Replica(s) already registered at %s", rse)
        return
    expect(resp, (200, 201), f"add_replicas {rse}")


def register_replica(
    token: str, rse: str, scope: str, name: str, pfn: str, size: int, adler32: str
) -> None:
    log.info("  Registering %s:%s @ %s (bytes=%d adler32=%s)", scope, name, rse, size, adler32)
    register_replicas(
        token,
        rse,
        [{"scope": scope, "name": name, "bytes": size, "adler32": adler32, "pfn": pfn}],
    )


def whoami(token: str) -> dict:
    resp = rucio_rest("/accounts/whoami", token)
    expect(resp, (200,), "whoami")
    return resp.json()


def rule_account(token: str) -> str:
    """Account to own new rules. Defaults to the token's own account."""
    return os.environ.get("RUCIO_RULE_ACCOUNT") or whoami(token)["account"]


def add_rule(token: str, scope: str, name: str, dst_rse: str, copies: int = 1) -> str:
    """Create a replication rule.

    `account` is required by the REST endpoint and load-bearing for the
    Rego: the self-service clause requires input.kwargs.account == issuer.
    """
    resp = rucio_rest(
        "/rules/",
        token,
        "POST",
        {
            "dids": [{"scope": scope, "name": name}],
            "copies": copies,
            "rse_expression": dst_rse,
            "account": rule_account(token),
        },
    )
    expect(resp, (201,), f"add_rule {scope}:{name} → {dst_rse}")
    rule_id = resp.json()[0]
    log.info("  ✓ Rule created: %s:%s → %s (%s)", scope, name, dst_rse, rule_id)
    return rule_id


def add_dataset(token: str, scope: str, name: str) -> None:
    resp = rucio_rest(f"/dids/{scope}/{name}", token, "POST", {"type": "DATASET"})
    expect(resp, (201, 409), f"add_dataset {scope}:{name}")


def attach_dids(token: str, scope: str, name: str, files: list, rse: str | None = None) -> None:
    body = {"dids": [{"scope": f["scope"], "name": f["name"]} for f in files]}
    if rse:
        body["rse"] = rse
    resp = rucio_rest(f"/dids/{scope}/{name}/dids", token, "POST", body)
    expect(resp, (200, 201), f"attach_dids → {scope}:{name}")


def validate_rule(token: str, rule_id: str, label: str, timeout: int = 300) -> None:
    """Poll until locks_ok >= 1 and locks_replicating == 0.

    rucio-daemons runs unconditionally in this stack and drives the conveyor
    itself — this just waits for it, it doesn't advance anything.
    """
    log.info("=== Validating rule %s (%s) ===", rule_id, label)
    deadline = time.time() + timeout
    ok = repl = stk = 0

    while time.time() < deadline:
        resp = rucio_rest(f"/rules/{rule_id}", token)
        if resp.status_code == 404:
            time.sleep(2)
            continue

        expect(resp, (200,), f"get_rule {rule_id}")
        rule = resp.json()
        ok = rule["locks_ok_cnt"]
        repl = rule["locks_replicating_cnt"]
        stk = rule["locks_stuck_cnt"]
        log.info(
            "  state=%-12s  OK=%-3d REPL=%-3d STUCK=%-3d", rule.get("state", "?"), ok, repl, stk
        )

        if stk > 0:
            raise RuntimeError(f"Rule {rule_id} ({label}) has {stk} stuck lock(s)")
        if ok >= 1 and repl == 0:
            log.info("  ✓ %s passed (rule_id=%s)", label, rule_id)
            return
        time.sleep(5)

    raise TimeoutError(
        f"Rule {rule_id} ({label}) did not converge within {timeout}s — "
        f"last: OK={ok} REPL={repl} STUCK={stk}"
    )


# ── WebDAV (container only — needs requests) ──────────────────────────────


def _auth_headers(token: str | None = None) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def webdav_put(url: str, token: str | None = None, content: bytes = b"", timeout: int = 30):
    return requests.put(
        url, headers=_auth_headers(token), data=content, verify=False, timeout=timeout
    )


def webdav_get(url: str, token: str | None = None, timeout: int = 30):
    return requests.get(url, headers=_auth_headers(token), verify=False, timeout=timeout)


def webdav_delete(url: str, token: str | None = None, timeout: int = 30):
    return requests.delete(url, headers=_auth_headers(token), verify=False, timeout=timeout)


def webdav_propfind(url: str, token: str | None = None, depth: str = "1", timeout: int = 240):
    headers = _auth_headers(token)
    headers["Depth"] = depth
    return requests.request("PROPFIND", url, headers=headers, verify=False, timeout=timeout)


def webdav_mkcol(url: str, token: str | None = None, timeout: int = 30):
    return requests.request(
        "MKCOL", url, headers=_auth_headers(token), verify=False, timeout=timeout
    )


def webdav_warm_up(
    base_url: str, path: str, label: str, token: str, retries: int = 6, interval: int = 10
) -> None:
    log.info("=== Warming up %s Storm-WebDAV instance ===", label)
    resp = None
    last_exc = None

    for attempt in range(1, retries + 1):
        try:
            resp = webdav_propfind(f"{base_url}{path}", token)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            log.info(
                "  [%d] %s request failed (%s) — retrying in %ds",
                attempt,
                label,
                exc.__class__.__name__,
                interval,
            )
            time.sleep(interval)
            continue

        if resp.status_code == 207:
            log.info("  ✓ %s Storm-WebDAV ready (HTTP 207)", label)
            return

        log.info(
            "  [%d] %s returned HTTP %s — retrying in %ds",
            attempt,
            label,
            resp.status_code,
            interval,
        )
        time.sleep(interval)

    raise AssertionError(
        f"{label} warm-up failed after {retries} attempts "
        f"(last HTTP {resp.status_code if resp else 'N/A'}"
        f"{', last error: ' + str(last_exc) if last_exc else ''})"
    )


def pfn_to_https(pfn: str) -> str:
    """XRootD's HTTP listener speaks TLS on the same port as davs://."""
    return pfn.replace("davs://", "https://", 1)


def pfn_path(pfn: str) -> str:
    return urlparse(pfn).path


def seed_xrd(pfn: str, token: str | None = None) -> tuple:
    """Seed a test file at the given PFN via WebDAV; return (size, adler32)."""
    content = b"rucio-test\n"
    url = pfn_to_https(pfn)

    webdav_put(url, token, content).raise_for_status()
    check = webdav_get(url, token)
    check.raise_for_status()
    if check.content != content:
        raise RuntimeError(f"seed_xrd: readback mismatch at {url}")

    return len(content), adler32_hex(content)


def adler32_hex(content: bytes) -> str:
    return "%08x" % (zlib.adler32(content) & 0xFFFFFFFF)


def prepare_xrd_dest(pfn: str, token: str | None = None) -> None:
    """Pre-create the destination directory via HTTP MKCOL."""
    remote_dir_url = pfn_to_https(pfn).rsplit("/", 1)[0]
    resp = webdav_mkcol(remote_dir_url, token)
    # 201 = created, 405/409 = already exists — both fine.
    if resp.status_code not in (201, 405, 409):
        raise RuntimeError(
            f"prepare_xrd_dest failed for {remote_dir_url}: HTTP {resp.status_code} {resp.text}"
        )


def seed_and_register_files(
    token: str, rse: str, scope: str, names: list, write_token: str | None = None
) -> list:
    """Seed files into an XRootD RSE and return Rucio replica dicts.

    `token` authenticates to Rucio; `write_token` is the storage-scoped token
    for the RSE endpoint. They are different credentials.
    """
    registered = []
    for name in names:
        pfn = compute_pfn(token, rse, scope, name)
        size, adler32 = seed_xrd(pfn, token=write_token)
        registered.append(
            {"scope": scope, "name": name, "bytes": size, "adler32": adler32, "pfn": pfn}
        )
        log.info("  seeded %s:%s → %s", scope, name, pfn)
    return registered


def prepare_xrd_dest_files(
    token: str, rse: str, scope: str, names: list, write_token: str | None = None
) -> None:
    """Pre-create destination directories on an XRootD RSE."""
    for name in names:
        prepare_xrd_dest(compute_pfn(token, rse, scope, name), token=write_token)
