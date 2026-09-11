"""
test_phase6_smoke.py — OIDC end-to-end transfer tests for dep-dlm-testbed.

Covers:
  - XRootD SciTokens TPC:  XRD3  → XRD4      (davs/SciTokens, FTS OIDC)
  - Teapot WebDAV TPC:     TEAPOT1 → TEAPOT2 (davs/bearer token, FTS OIDC)
  - Cross-protocol, both directions
  - Dataset registration and replication

Rucio is driven over REST (see conftest.rucio_rest) rather than the Python
client, so no rucio.cfg is needed in the test container. Storage endpoints
are still driven directly with per-audience tokens from Keycloak.

Prerequisites (handled by scripts/init-testbed.sh):
  - RSEs XRD3, XRD4, TEAPOT1, TEAPOT2 registered with OIDC attributes
  - FTS t_token_provider seeded with keycloak-rucio issuer entries
  - Rucio accounts ddmlab / randomaccount with quota on all four RSEs

The Rucio credential comes from the rucio_token fixture, which defaults to
userpass-as-root. That is deliberate: this suite tests transfers, not
authorisation, and root short-circuits the Rego. The claims path is covered
by test_phase6_authz.py. Set RUCIO_AUTH=oidc to run this suite
token-natively once the Rego covers its actions (BACKLOG 3a).
"""

import binascii
import logging
import time
import zlib
from urllib.parse import urlparse

from conftest import (
    TEAPOT1_URL,
    add_dataset,
    add_rule,
    attach_dids,
    compute_pfn,
    prepare_xrd_dest,
    prepare_xrd_dest_files,
    register_replica,
    register_replicas,
    seed_and_register_files,
    seed_xrd,
    validate_rule,
    webdav_delete,
    webdav_get,
    webdav_put,
)

log = logging.getLogger("test-transfers")

SCOPE = "ddmlab"


# ── XRootD SciTokens: XRD3 → XRD4 ───────────────────────────────────────


class TestXRootDOIDC:
    """
    XRootD SciTokens TPC via FTS OIDC.

    The transfer uses davs:// (HTTP-TPC) rather than xroot:// because
    XRootD SciTokens auth for third-party copy requires HTTP/WebDAV.
    FTS issues a storage.read + storage.modify token from Keycloak
    (audience: xrd3 / xrd4) and performs an HTTP COPY between the two
    XRootD endpoints.
    """

    def test_xrd3_to_xrd4(self, rucio_token, xrd3_write_token, xrd4_write_token):
        """Replicate a file from XRD3 to XRD4 via SciTokens + FTS OIDC."""
        name = f"xrd-oidc-{int(time.time())}"
        log.info("[ XRD3 → XRD4  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "XRD4", SCOPE, name)
        log.info("  src PFN: %s", src_pfn)
        log.info("  dst PFN: %s", dst_pfn)

        size, adler32 = seed_xrd("xrd3", src_pfn, token=xrd3_write_token)
        log.info("  seeded %d bytes  adler32=%s", size, adler32)

        # Pre-create destination directory (auth-enforced — needs a
        # write-scoped token for the destination RSE)
        prepare_xrd_dest(dst_pfn, token=xrd4_write_token)

        register_replica(rucio_token, "XRD3", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "XRD4")

        # Wait for rucio-daemons (always-on) to converge the rule
        validate_rule(rucio_token, rule_id, "XRD3→XRD4 SciTokens")


# ── Teapot WebDAV: TEAPOT1 → TEAPOT2 ─────────────────────────────────────


class TestTeapotOIDC:
    """
    Teapot WebDAV OIDC TPC via FTS OIDC.

    Teapot is a multi-tenancy WebDAV proxy in front of per-user Storm-WebDAV
    JVMs. It validates bearer tokens issued by Keycloak (audience: teapot).
    FTS performs an HTTP COPY (TPC pull) between teapot1 and teapot2 using a
    token obtained via the t_token_provider entry registered during init.

    Source file is seeded via an authenticated WebDAV PUT (no filesystem
    exec available for Teapot).
    """

    def test_teapot1_to_teapot2(self, rucio_token, teapot_token, teapots_ready):
        """Replicate a file from TEAPOT1 to TEAPOT2 via bearer token + FTS OIDC."""
        name = f"teapot-{int(time.time())}"
        seed_content = b"rucio-teapot-oidc-test\n"
        log.info("[ TEAPOT1 → TEAPOT2  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "TEAPOT2", SCOPE, name)
        log.info("  src PFN: %s", src_pfn)
        log.info("  dst PFN: %s", dst_pfn)

        src_path = urlparse(src_pfn).path  # e.g. /data/ddmlab/ab/cd/teapot-...

        # Clean up any stale file from a previous run
        webdav_delete(f"{TEAPOT1_URL}{src_path}", teapot_token)

        resp = webdav_put(f"{TEAPOT1_URL}{src_path}", teapot_token, seed_content)
        assert resp.status_code in {200, 201, 204}, (
            f"Seed PUT returned HTTP {resp.status_code}: {resp.text[:200]}"
        )
        log.info("  ✓ Seeded via WebDAV PUT (HTTP %s)", resp.status_code)

        verify = webdav_get(f"{TEAPOT1_URL}{src_path}", teapot_token)
        assert verify.status_code == 200, (
            f"Seed not readable: GET {TEAPOT1_URL}{src_path} → HTTP {verify.status_code}"
        )
        log.info("  ✓ Seed confirmed readable (HTTP 200)")

        # Compute checksum locally (Teapot PROPFIND does not expose adler32)
        adler32 = binascii.hexlify(zlib.adler32(seed_content).to_bytes(4, "big")).decode()
        size = len(seed_content)

        register_replica(rucio_token, "TEAPOT1", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "TEAPOT2")

        validate_rule(rucio_token, rule_id, "TEAPOT1→TEAPOT2 WebDAV OIDC")


# ── Cross-protocol: XRootD SciTokens ↔ Teapot WebDAV ─────────────────────


class TestCrossProtocolOIDC:
    """
    Cross-protocol OIDC TPC via FTS OIDC.

    Exercises FTS obtaining tokens for two different audiences at once:
      - XRD3 audience:    xrd3    (SciTokens)
      - TEAPOT1 audience: teapot  (WebDAV bearer)

    FTS uses the t_token_provider Keycloak entry to perform token exchange
    for each endpoint independently. The HTTP COPY is davs:// on both sides
    since XRootD exposes HTTP on port 1094.
    """

    def test_xrd3_to_teapot1(self, rucio_token, teapots_ready, xrd3_write_token):
        """XRD3 (SciTokens) → TEAPOT1 (WebDAV): seed via xrd3, dest via Teapot."""
        name = f"xrd-to-teapot-{int(time.time())}"
        log.info("[ XRD3 → TEAPOT1  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        log.info("  src PFN: %s", src_pfn)
        log.info("  dst PFN: %s", dst_pfn)

        size, adler32 = seed_xrd("xrd3", src_pfn, token=xrd3_write_token)
        log.info("  seeded %d bytes  adler32=%s", size, adler32)

        register_replica(rucio_token, "XRD3", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "TEAPOT1")

        validate_rule(rucio_token, rule_id, "XRD3→TEAPOT1 cross-protocol")

    def test_teapot1_to_xrd3(self, rucio_token, teapot_token, teapots_ready, xrd3_write_token):
        """TEAPOT1 (WebDAV) → XRD3 (SciTokens): seed via WebDAV PUT, dest via xrd3."""
        name = f"teapot-to-xrd-{int(time.time())}"
        seed_content = b"rucio-teapot-to-xrd-test\n"
        log.info("[ TEAPOT1 → XRD3  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        log.info("  src PFN: %s", src_pfn)
        log.info("  dst PFN: %s", dst_pfn)

        src_path = urlparse(src_pfn).path
        webdav_delete(f"{TEAPOT1_URL}{src_path}", teapot_token)
        resp = webdav_put(f"{TEAPOT1_URL}{src_path}", teapot_token, seed_content)
        assert resp.status_code in {200, 201, 204}, (
            f"Seed PUT returned HTTP {resp.status_code}: {resp.text[:200]}"
        )
        log.info("  ✓ Seeded via WebDAV PUT (HTTP %s)", resp.status_code)

        verify = webdav_get(f"{TEAPOT1_URL}{src_path}", teapot_token)
        assert verify.status_code == 200, (
            f"Seed not readable: GET {TEAPOT1_URL}{src_path} → HTTP {verify.status_code}"
        )
        log.info("  ✓ Seed confirmed readable (HTTP 200)")

        # Pre-create destination directory on xrd3 — auth-enforced, needs a
        # write-scoped token
        prepare_xrd_dest(dst_pfn, token=xrd3_write_token)

        adler32 = binascii.hexlify(zlib.adler32(seed_content).to_bytes(4, "big")).decode()
        size = len(seed_content)

        register_replica(rucio_token, "TEAPOT1", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "XRD3")

        validate_rule(rucio_token, rule_id, "TEAPOT1→XRD3 cross-protocol")


# ── Dataset operations: XRD3 ──────────────────────────────────────────────


class TestDatasetOIDC:
    """
    Rucio dataset registration and replication via XRD3→XRD4 (OIDC).

    Demonstrates the two dataset population patterns:
      - create a dataset and attach its initial replicas
      - extend an existing dataset with new replicas
    """

    def test_add_dataset(self, rucio_token, xrd3_write_token, xrd4_write_token):
        """Register two files into a new dataset on XRD3, replicate to XRD4."""
        ts = int(time.time())
        dataset = f"oidc-dataset-{ts}"
        names = [f"{dataset}-file1", f"{dataset}-file2"]
        log.info("[ add_dataset: XRD3 (seed 2 files) → XRD4 ]")

        files = seed_and_register_files(
            rucio_token, "XRD3", SCOPE, names, "xrd3", write_token=xrd3_write_token
        )
        prepare_xrd_dest_files(rucio_token, "XRD4", SCOPE, names, write_token=xrd4_write_token)

        register_replicas(rucio_token, "XRD3", files)
        log.info("  Creating dataset %s:%s with %d files", SCOPE, dataset, len(files))
        add_dataset(rucio_token, SCOPE, dataset)
        attach_dids(rucio_token, SCOPE, dataset, files, rse="XRD3")
        log.info("  ✓ Dataset registered")

        rule_id = add_rule(rucio_token, SCOPE, dataset, "XRD4")
        validate_rule(rucio_token, rule_id, "add_dataset XRD3→XRD4")

    def test_add_files_to_dataset(self, rucio_token, xrd3_write_token, xrd4_write_token):
        """Append two files to an existing dataset on XRD3, replicate to XRD4."""
        ts = int(time.time())
        dataset = f"oidc-existing-dataset-{ts}"
        names = [f"{dataset}-v2-file1", f"{dataset}-v2-file2"]
        log.info("[ add_files_to_dataset: extend existing dataset → XRD4 ]")

        add_dataset(rucio_token, SCOPE, dataset)
        log.info("  Created empty dataset %s:%s", SCOPE, dataset)

        files = seed_and_register_files(
            rucio_token, "XRD3", SCOPE, names, "xrd3", write_token=xrd3_write_token
        )
        prepare_xrd_dest_files(rucio_token, "XRD4", SCOPE, names, write_token=xrd4_write_token)

        register_replicas(rucio_token, "XRD3", files)
        log.info("  Appending %d files to %s:%s", len(files), SCOPE, dataset)
        attach_dids(rucio_token, SCOPE, dataset, files, rse="XRD3")
        log.info("  ✓ Files appended")

        rule_id = add_rule(rucio_token, SCOPE, dataset, "XRD4")
        validate_rule(rucio_token, rule_id, "add_files_to_dataset XRD3→XRD4")
