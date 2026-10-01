"""
Phase 6 — OIDC end-to-end transfer tests.

Covers:
  - XRootD SciTokens TPC:  XRD3  → XRD4      (davs/SciTokens, FTS OIDC)
  - Teapot WebDAV TPC:     TEAPOT1 → TEAPOT2 (davs/bearer token, FTS OIDC)
  - Cross-protocol, both directions
  - Dataset registration and replication

Runs as root by default (RUCIO_AUTH=userpass), which the Rego
short-circuits: this suite tests transfers, not authorisation.
"""

import logging
import time

from helpers import (
    TEAPOT1_URL,
    add_dataset,
    add_rule,
    adler32_hex,
    attach_dids,
    compute_pfn,
    pfn_path,
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


def seed_teapot(pfn: str, token: str, content: bytes) -> None:
    """Seed a file on TEAPOT1 via authenticated WebDAV PUT and read it back.

    Teapot has no filesystem exec, so WebDAV is the only way in. Any stale
    file from a previous run is removed first.
    """
    url = f"{TEAPOT1_URL}{pfn_path(pfn)}"
    webdav_delete(url, token)

    resp = webdav_put(url, token, content)
    assert resp.status_code in {200, 201, 204}, (
        f"Seed PUT returned HTTP {resp.status_code}: {resp.text[:200]}"
    )
    log.info("  ✓ Seeded via WebDAV PUT (HTTP %s)", resp.status_code)

    verify = webdav_get(url, token)
    assert verify.status_code == 200, f"Seed not readable: GET {url} → HTTP {verify.status_code}"
    log.info("  ✓ Seed confirmed readable (HTTP 200)")


def log_pfns(src_pfn: str, dst_pfn: str) -> None:
    log.info("  src PFN: %s", src_pfn)
    log.info("  dst PFN: %s", dst_pfn)


class TestXRootDOIDC:
    """XRootD SciTokens TPC via FTS OIDC.

    davs:// (HTTP-TPC) rather than xroot://: SciTokens auth for third-party
    copy requires HTTP/WebDAV. FTS obtains a storage.read + storage.modify
    token (audience xrd3 / xrd4) and performs an HTTP COPY between the two.
    """

    def test_xrd3_to_xrd4(self, rucio_token, xrd3_write_token, xrd4_write_token):
        name = f"xrd-oidc-{int(time.time())}"
        log.info("[ XRD3 → XRD4  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "XRD4", SCOPE, name)
        log_pfns(src_pfn, dst_pfn)

        size, adler32 = seed_xrd(src_pfn, token=xrd3_write_token)
        log.info("  seeded %d bytes  adler32=%s", size, adler32)
        # Auth-enforced — needs a write-scoped token for the destination RSE.
        prepare_xrd_dest(dst_pfn, token=xrd4_write_token)

        register_replica(rucio_token, "XRD3", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "XRD4")
        validate_rule(rucio_token, rule_id, "XRD3→XRD4 SciTokens")


class TestTeapotOIDC:
    """Teapot WebDAV OIDC TPC via FTS OIDC.

    Teapot is a multi-tenancy WebDAV proxy in front of per-user Storm-WebDAV
    JVMs, validating bearer tokens (audience teapot). FTS performs an HTTP
    COPY using a token from the t_token_provider entry registered at init.
    """

    def test_teapot1_to_teapot2(self, rucio_token, teapot_token, teapots_ready):
        name = f"teapot-{int(time.time())}"
        content = b"rucio-teapot-oidc-test\n"
        log.info("[ TEAPOT1 → TEAPOT2  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "TEAPOT2", SCOPE, name)
        log_pfns(src_pfn, dst_pfn)

        seed_teapot(src_pfn, teapot_token, content)
        # Teapot PROPFIND does not expose adler32, so compute it locally.
        register_replica(
            rucio_token, "TEAPOT1", SCOPE, name, src_pfn, len(content), adler32_hex(content)
        )
        rule_id = add_rule(rucio_token, SCOPE, name, "TEAPOT2")
        validate_rule(rucio_token, rule_id, "TEAPOT1→TEAPOT2 WebDAV OIDC")


class TestCrossProtocolOIDC:
    """Cross-protocol OIDC TPC: FTS obtains tokens for two audiences at once
    (xrd3 SciTokens, teapot WebDAV bearer), exchanging for each endpoint
    independently. davs:// on both sides — XRootD exposes HTTP on 1094."""

    def test_xrd3_to_teapot1(self, rucio_token, teapots_ready, xrd3_write_token):
        name = f"xrd-to-teapot-{int(time.time())}"
        log.info("[ XRD3 → TEAPOT1  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        log_pfns(src_pfn, dst_pfn)

        size, adler32 = seed_xrd(src_pfn, token=xrd3_write_token)
        log.info("  seeded %d bytes  adler32=%s", size, adler32)

        register_replica(rucio_token, "XRD3", SCOPE, name, src_pfn, size, adler32)
        rule_id = add_rule(rucio_token, SCOPE, name, "TEAPOT1")
        validate_rule(rucio_token, rule_id, "XRD3→TEAPOT1 cross-protocol")

    def test_teapot1_to_xrd3(self, rucio_token, teapot_token, teapots_ready, xrd3_write_token):
        name = f"teapot-to-xrd-{int(time.time())}"
        content = b"rucio-teapot-to-xrd-test\n"
        log.info("[ TEAPOT1 → XRD3  name=%s ]", name)

        src_pfn = compute_pfn(rucio_token, "TEAPOT1", SCOPE, name)
        dst_pfn = compute_pfn(rucio_token, "XRD3", SCOPE, name)
        log_pfns(src_pfn, dst_pfn)

        seed_teapot(src_pfn, teapot_token, content)
        prepare_xrd_dest(dst_pfn, token=xrd3_write_token)

        register_replica(
            rucio_token, "TEAPOT1", SCOPE, name, src_pfn, len(content), adler32_hex(content)
        )
        rule_id = add_rule(rucio_token, SCOPE, name, "XRD3")
        validate_rule(rucio_token, rule_id, "TEAPOT1→XRD3 cross-protocol")


class TestDatasetOIDC:
    """Dataset registration and replication via XRD3 → XRD4: create a dataset
    with its initial replicas, and extend an existing one."""

    def _seed(self, rucio_token, names, xrd3_write_token, xrd4_write_token):
        files = seed_and_register_files(
            rucio_token, "XRD3", SCOPE, names, write_token=xrd3_write_token
        )
        prepare_xrd_dest_files(rucio_token, "XRD4", SCOPE, names, write_token=xrd4_write_token)
        register_replicas(rucio_token, "XRD3", files)
        return files

    def test_add_dataset(self, rucio_token, xrd3_write_token, xrd4_write_token):
        dataset = f"oidc-dataset-{int(time.time())}"
        names = [f"{dataset}-file1", f"{dataset}-file2"]
        log.info("[ add_dataset: XRD3 (seed 2 files) → XRD4 ]")

        files = self._seed(rucio_token, names, xrd3_write_token, xrd4_write_token)
        add_dataset(rucio_token, SCOPE, dataset)
        attach_dids(rucio_token, SCOPE, dataset, files, rse="XRD3")
        log.info("  ✓ Dataset %s:%s registered with %d files", SCOPE, dataset, len(files))

        rule_id = add_rule(rucio_token, SCOPE, dataset, "XRD4")
        validate_rule(rucio_token, rule_id, "add_dataset XRD3→XRD4")

    def test_add_files_to_dataset(self, rucio_token, xrd3_write_token, xrd4_write_token):
        dataset = f"oidc-existing-dataset-{int(time.time())}"
        names = [f"{dataset}-v2-file1", f"{dataset}-v2-file2"]
        log.info("[ add_files_to_dataset: extend existing dataset → XRD4 ]")

        add_dataset(rucio_token, SCOPE, dataset)
        files = self._seed(rucio_token, names, xrd3_write_token, xrd4_write_token)
        attach_dids(rucio_token, SCOPE, dataset, files, rse="XRD3")
        log.info("  ✓ Appended %d files to %s:%s", len(files), SCOPE, dataset)

        rule_id = add_rule(rucio_token, SCOPE, dataset, "XRD4")
        validate_rule(rucio_token, rule_id, "add_files_to_dataset XRD3→XRD4")
