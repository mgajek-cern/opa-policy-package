"""
conftest.py — shared fixtures and helpers for phase6-opa OIDC transfer tests.

Covers XRootD SciTokens (xrd3/xrd4) and Teapot WebDAV (teapot1/teapot2)
against the local Keycloak container. Docker Compose only — rucio-daemons
runs continuously, so validate_rule just waits for it rather than driving
--run-once daemons the way dep-dlm-testbed's runtime-agnostic version does.
"""

import logging
import os
import subprocess
import time
import zlib

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("conftest")

# ── Service constants ─────────────────────────────────────────────────────

VALSTORAGE_HOST = os.environ.get("VALIDATION_STORAGE_HOST")
TEAPOT1_URL = os.environ.get("TEAPOT1_URL") or (
    f"https://{VALSTORAGE_HOST}:8081" if VALSTORAGE_HOST else "https://teapot1:8081"
)
TEAPOT2_URL = os.environ.get("TEAPOT2_URL") or (
    f"https://{VALSTORAGE_HOST}:8082" if VALSTORAGE_HOST else "https://teapot2:8081"
)

CFG_RUCIO = "/opt/rucio/etc/rucio.cfg"

# ── OIDC provider config (env-overridable; defaults = local Keycloak) ─────
#
# docker-compose.yml sets these on rucio-client, but the defaults here must
# describe the local Keycloak too — a Keycloak realm's token endpoint is under
# /protocol/openid-connect/token, not /token, and only the password grant
# yields offline_access (a service account has no user session to hang an
# offline token off).

OIDC_ISSUER = os.environ.get("OIDC_ISSUER") or "https://keycloak:8443/realms/rucio"
OIDC_TOKEN_URL = (
    os.environ.get("OIDC_TOKEN_URL")
    or f"{OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/token"
)
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID") or "rucio"
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET") or "rucio-secret"
OIDC_USERNAME = os.environ.get("OIDC_USERNAME") or "randomaccount"
OIDC_PASSWORD = os.environ.get("OIDC_PASSWORD") or "secret"
OIDC_GRANT_TYPE = (
    os.environ.get("OIDC_GRANT_TYPE") or "password"
)  # password | client_credentials

OIDC_EXPECTED_SCOPE = (
    os.environ.get("OIDC_EXPECTED_SCOPE") or "openid storage.read:/ storage.modify:/"
)
OIDC_TEAPOT_AUD_SCOPE = (
    os.environ.get("OIDC_TEAPOT_AUD_SCOPE") or "aud:teapot1 aud:teapot2"
)

# RFC 8707 resource indicators require a URI. Keycloak's aud:* scope syntax
# works with bare RSE names, so this is only consulted under
# client_credentials (the LS AAI/EGI path); under the password grant it never
# reaches the token request.
OIDC_RESOURCE_SUFFIX = os.environ.get("OIDC_RESOURCE_SUFFIX") or ".example.org"

XRDFS_TRANSIENT_ERR = "resource temporarily unavailable"


def _rse_resource(name: str) -> str:
    """Map a bare RSE name to the URI form LS AAI/EGI expects as resource=."""
    if OIDC_GRANT_TYPE != "client_credentials":
        return name
    return f"https://{name}{OIDC_RESOURCE_SUFFIX}/"


def _auth_headers(token: str = None) -> dict:
    """Shared header-building for the webdav_* helpers — omit Authorization
    entirely when no token is given, rather than sending `Bearer None`."""
    return {"Authorization": f"Bearer {token}"} if token else {}


# ── Rucio client (Python API) ─────────────────────────────────────────────


def make_client():
    """Build a Rucio Python client from the mounted config."""
    from rucio.client import Client
    from rucio.common.config import get_config

    conf = get_config()
    conf.read(CFG_RUCIO)
    auth_type = conf.get("client", "auth_type")

    creds = None
    if auth_type == "userpass":
        creds = {
            "username": conf.get("client", "username"),
            "password": conf.get("client", "password"),
        }

    return Client(
        rucio_host=conf.get("client", "rucio_host"),
        auth_host=conf.get("client", "auth_host"),
        account=conf.get("client", "account"),
        auth_type=auth_type,
        creds=creds,
        vo=conf.get("client", "vo", fallback="def"),
    )


# ── PFN computation ───────────────────────────────────────────────────────


def compute_pfn(client, rse: str, scope: str, name: str) -> str:
    """Compute the write PFN for a DID on a given RSE."""
    from rucio.rse import rsemanager as rsemgr

    rse_info = rsemgr.get_rse_info(rse=rse, vo=client.vo)
    return list(
        rsemgr.lfns2pfns(
            rse_info,
            [{"scope": scope, "name": name}],
            operation="write",
        ).values()
    )[0]


# ── Rucio rule helpers ────────────────────────────────────────────────────


def register_replica(
    client, rse: str, scope: str, name: str, pfn: str, size: int, adler32: str
) -> None:
    from rucio.common.exception import Duplicate, RucioException

    log.info(
        "  Registering %s:%s @ %s (bytes=%d adler32=%s)",
        scope,
        name,
        rse,
        size,
        adler32,
    )
    try:
        client.add_replicas(
            rse=rse,
            files=[
                {
                    "scope": scope,
                    "name": name,
                    "bytes": size,
                    "adler32": adler32,
                    "pfn": pfn,
                }
            ],
        )
    except Duplicate:
        log.warning("  Replica %s:%s already exists at %s", scope, name, rse)
    except RucioException as e:
        log.error("  Registration failed: %s", e)
        raise


def add_rule(client, scope: str, name: str, dst_rse: str) -> str:
    rule_id = client.add_replication_rule(
        dids=[{"scope": scope, "name": name}], copies=1, rse_expression=dst_rse
    )[0]
    log.info("  ✓ Rule created: %s:%s → %s (%s)", scope, name, dst_rse, rule_id)
    return rule_id


def validate_rule(
    client,
    rule_id: str,
    label: str,
    rucio_svc: str = "rucio-server",
    timeout: int = 300,
) -> None:
    """Poll until locks_ok >= 1 and locks_replicating == 0.

    rucio-daemons runs unconditionally in this stack and drives the conveyor
    itself — this just waits for it, it doesn't advance anything.
    """
    from rucio.common.exception import RuleNotFound

    log.info("=== Validating rule %s (%s) ===", rule_id, label)
    deadline = time.time() + timeout
    ok = repl = stk = 0

    while time.time() < deadline:
        try:
            rule = client.get_replication_rule(rule_id)
        except RuleNotFound:
            time.sleep(2)
            continue

        ok = rule["locks_ok_cnt"]
        repl = rule["locks_replicating_cnt"]
        stk = rule["locks_stuck_cnt"]
        log.info(
            "  state=%-12s  OK=%-3d REPL=%-3d STUCK=%-3d",
            rule.get("state", "?"),
            ok,
            repl,
            stk,
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


# ── XRootD SciTokens (shells out — no HTTP equivalent for these checks) ────


def _xrdfs_run(
    args: list, retries: int = 3, backoff: float = 3.0, **kwargs
) -> subprocess.CompletedProcess:
    """subprocess.run(["xrdfs", *args], ...) with retry-on-transient-TLS-error."""
    out = None
    for attempt in range(1, retries + 1):
        out = subprocess.run(["xrdfs", *args], **kwargs)
        stderr = out.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        stderr = stderr or ""
        if out.returncode == 0 or XRDFS_TRANSIENT_ERR not in stderr.lower():
            return out
        if attempt < retries:
            log.info(
                "  [%d/%d] transient xrdfs TLS error, retrying in %ss...",
                attempt,
                retries,
                backoff,
            )
            time.sleep(backoff)
    return out


def _xrdcp_run(
    args: list, retries: int = 3, backoff: float = 3.0, **kwargs
) -> subprocess.CompletedProcess:
    """subprocess.run(["xrdcp", *args], ...) with the same transient-TLS
    retry as _xrdfs_run. xrdcp is normally called with check=True, so its
    failure mode is CalledProcessError rather than a returncode — this
    catches that specifically instead of inspecting .returncode."""
    for attempt in range(1, retries + 1):
        try:
            return subprocess.run(["xrdcp", *args], **kwargs)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            stderr = stderr or ""
            if attempt < retries and XRDFS_TRANSIENT_ERR in stderr.lower():
                log.info(
                    "  [%d/%d] transient xrdcp TLS error, retrying in %ss...",
                    attempt,
                    retries,
                    backoff,
                )
                time.sleep(backoff)
                continue
            raise


# ── Keycloak token helpers ────────────────────────────────────────────────


def fetch_token_password(
    url: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    scope: str = "openid",
) -> str:
    resp = requests.post(
        url,
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": scope,
        },
        auth=(client_id, client_secret),
        verify=False,
        timeout=10,
    )
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise requests.exceptions.HTTPError(f"{e}: {resp.text}", response=resp) from None
    return resp.json()["access_token"]


def fetch_token_client_credentials(
    url: str,
    client_id: str,
    client_secret: str,
    scope: str = "openid",
    resource=None,  # str, list[str], or None
) -> str:
    data = {"grant_type": "client_credentials", "scope": scope}
    if resource:
        # RFC 8707: resource stamps the aud claim; audience= does not.
        # requests encodes a list value as repeated resource= form fields,
        # which is how RFC 8707 expresses multiple audiences in one request.
        data["resource"] = resource
    resp = requests.post(
        url,
        data=data,
        auth=(client_id, client_secret),
        verify=False,
        timeout=10,
    )
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise requests.exceptions.HTTPError(f"{e}: {resp.text}", response=resp) from None
    return resp.json()["access_token"]


# ── WebDAV helpers ────────────────────────────────────────────────────────
# Shared HTTP primitives — seed_xrd/prepare_xrd_dest below are thin PFN->URL
# wrappers around these, not a separate filesystem-based path. XRootD's
# libXrdHttp and Teapot's Storm-WebDAV both speak plain WebDAV/HTTP with a
# bearer token; the only real difference is that callers here work with a
# Rucio PFN (davs://...) rather than an already-built URL.


def webdav_put(
    url: str, token: str = None, content: bytes = b"", timeout: int = 30
) -> requests.Response:
    return requests.put(
        url,
        headers=_auth_headers(token),
        data=content,
        verify=False,
        timeout=timeout,
    )


def webdav_get(url: str, token: str = None, timeout: int = 30) -> requests.Response:
    return requests.get(
        url,
        headers=_auth_headers(token),
        verify=False,
        timeout=timeout,
    )


def webdav_delete(url: str, token: str = None, timeout: int = 30) -> requests.Response:
    return requests.delete(
        url,
        headers=_auth_headers(token),
        verify=False,
        timeout=timeout,
    )


def webdav_propfind(
    url: str, token: str = None, depth: str = "1", timeout: int = 240
) -> requests.Response:
    headers = _auth_headers(token)
    headers["Depth"] = depth
    return requests.request(
        "PROPFIND",
        url,
        headers=headers,
        verify=False,
        timeout=timeout,
    )


def webdav_mkcol(url: str, token: str = None, timeout: int = 30) -> requests.Response:
    return requests.request(
        "MKCOL", url, headers=_auth_headers(token), verify=False, timeout=timeout
    )


def webdav_warm_up(
    base_url: str,
    path: str,
    label: str,
    token: str,
    retries: int = 6,
    interval: int = 10,
) -> None:
    log.info("=== Warming up %s Storm-WebDAV instance ===", label)
    resp = None
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = webdav_propfind(f"{base_url}{path}", token)
        except requests.exceptions.RequestException as e:
            last_exc = e
            log.info(
                "  [%d] %s request failed (%s) — retrying in %ds",
                attempt,
                label,
                e.__class__.__name__,
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


# ── PFN-based seeding (XRootD RSEs — Teapot tests call webdav_* directly) ──


def _pfn_to_https(pfn: str) -> str:
    """XRootD's HTTP listener speaks TLS on the same port as davs://."""
    return pfn.replace("davs://", "https://", 1)


def seed_xrd(svc: str, pfn: str, token: str = None) -> tuple[int, str]:
    """Seed a test file at the given PFN — a thin PFN->URL wrapper around
    webdav_put/webdav_get, matching how FTS itself performs the real
    transfer. `svc` is only used for logging."""
    content = b"rucio-test\n"
    url = _pfn_to_https(pfn)

    resp = webdav_put(url, token, content)
    resp.raise_for_status()

    # Read back to confirm the write actually landed, rather than trusting
    # a 2xx status alone.
    check = webdav_get(url, token)
    check.raise_for_status()
    if check.content != content:
        raise RuntimeError(f"seed_xrd: readback mismatch at {url}")

    adler = "%08x" % (zlib.adler32(content) & 0xFFFFFFFF)
    return len(content), adler


def prepare_xrd_dest(pfn: str, token: str = None) -> None:
    """Pre-create the destination directory via HTTP MKCOL, matching seed_xrd.

    XRootD needs this explicit MKCOL before a first write to a new
    directory; Teapot's storage area auto-creates intermediate directories,
    so TestTeapotOIDC has no equivalent call before its webdav_put.
    """
    remote_dir_url = _pfn_to_https(pfn).rsplit("/", 1)[0]
    resp = webdav_mkcol(remote_dir_url, token)
    # 201 = created, 405/409 = already exists — both fine; anything else is real
    if resp.status_code not in (201, 405, 409):
        raise RuntimeError(
            f"prepare_xrd_dest failed for {remote_dir_url}: HTTP {resp.status_code} {resp.text}"
        )


def seed_and_register_files(
    client, rse: str, scope: str, names: list[str], seed_svc: str, token: str = None
) -> list[dict]:
    """Seed files into an XRootD RSE and return Rucio replica dicts."""
    registered = []
    for name in names:
        pfn = compute_pfn(client, rse, scope, name)
        size, adler32 = seed_xrd(seed_svc, pfn, token=token)
        registered.append(
            {
                "scope": scope,
                "name": name,
                "bytes": size,
                "adler32": adler32,
                "pfn": pfn,
            }
        )
        log.info("  seeded %s:%s → %s", scope, name, pfn)
    return registered


def prepare_xrd_dest_files(
    client, rse: str, scope: str, names: list[str], token: str = None
) -> None:
    """Pre-create destination directories on an XRootD RSE for a list of DIDs."""
    for name in names:
        pfn = compute_pfn(client, rse, scope, name)
        prepare_xrd_dest(pfn, token=token)


# ── Session-scoped fixtures ───────────────────────────────────────────────


@pytest.fixture(scope="session")
def rucio_client():
    """Rucio Python client (userpass, single OIDC instance)."""
    return make_client()


def _mint(scope: str, resource: str = None) -> str:
    if OIDC_GRANT_TYPE == "client_credentials":
        return fetch_token_client_credentials(
            OIDC_TOKEN_URL,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            scope=scope,
            resource=resource,
        )
    return fetch_token_password(
        OIDC_TOKEN_URL,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
        OIDC_USERNAME,
        OIDC_PASSWORD,
        scope=scope,
    )


@pytest.fixture(scope="session")
def oidc_token():
    return _mint(OIDC_EXPECTED_SCOPE, resource=_rse_resource("xrd4"))


@pytest.fixture(scope="session")
def teapot_token():
    # On Keycloak the audience comes from the aud:teapot* client scopes; on
    # LS AAI/EGI that syntax is invalid_scope and resource= carries it instead.
    #
    # This single token is used against BOTH teapot1 and teapot2 (see
    # teapots_ready below), so under client_credentials it must carry both
    # audiences — request resource= for each RSE rather than just teapot1.
    if OIDC_GRANT_TYPE == "client_credentials":
        return fetch_token_client_credentials(
            OIDC_TOKEN_URL,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            scope=OIDC_EXPECTED_SCOPE,
            resource=[_rse_resource("teapot1"), _rse_resource("teapot2")],
        )
    scope = " ".join(filter(None, [OIDC_EXPECTED_SCOPE, OIDC_TEAPOT_AUD_SCOPE]))
    return fetch_token_password(
        OIDC_TOKEN_URL,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
        OIDC_USERNAME,
        OIDC_PASSWORD,
        scope=scope,
    )


@pytest.fixture(scope="session")
def teapots_ready(teapot_token):
    """Warm up both Teapot Storm-WebDAV JVMs before any transfer test runs."""
    webdav_warm_up(TEAPOT1_URL, "/data/", "teapot1", teapot_token)
    webdav_warm_up(TEAPOT2_URL, "/data/", "teapot2", teapot_token)
    return True


@pytest.fixture(scope="session")
def xrd3_write_token():
    """Token scoped for writing to XRD3 — needed by seed_xrd/prepare_xrd_dest
    now that both write over the real protocol (auth-enforced) instead of
    exec (auth-bypassing)."""
    return _mint(OIDC_EXPECTED_SCOPE, resource=_rse_resource("xrd3"))


@pytest.fixture(scope="session")
def xrd4_write_token():
    """Token scoped for writing to XRD4 — destination side of XRD3→XRD4
    transfers and the dataset tests; needed now that prepare_xrd_dest is
    protocol-based (auth-enforced) instead of exec-based."""
    return _mint(OIDC_EXPECTED_SCOPE, resource=_rse_resource("xrd4"))
