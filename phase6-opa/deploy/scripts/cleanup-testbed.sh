#!/usr/bin/env bash
set -euo pipefail

_exec() {
    local svc=$1; shift
    docker exec "deploy-${svc}-1" "$@"
}

ra() { _exec rucio-server rucio-admin -S userpass -u ddmlab --password secret "$@"; }

ALL_RSES=(XRD3 XRD4 TEAPOT1 TEAPOT2 COPERNICUS_S3)
TEST_SCOPES=(ddmlab randomaccount test)

# ── Rule + replica cleanup ──────────────────────────────────────

delete_test_rules_and_replicas() {
    echo "=== Deleting replication rules (scopes: ${TEST_SCOPES[*]}) ==="

    _exec rucio-server env \
        TEST_SCOPES="$(IFS=,; echo "${TEST_SCOPES[*]}")" \
        python3 -c "
import os
from rucio.client import Client
from rucio.common.exception import RucioException

client = Client()
scopes = [s for s in os.environ['TEST_SCOPES'].split(',') if s]

deleted = 0
for scope in scopes:
    try:
        dids = list(client.list_dids(scope=scope, filters={}))
    except RucioException as e:
        print(f'  ⚠ Could not list DIDs in scope {scope}: {e}')
        continue
    for name in dids:
        try:
            rules = list(client.list_did_rules(scope=scope, name=name))
        except RucioException:
            continue
        for rule in rules:
            rid = rule['id']
            try:
                client.delete_replication_rule(rid, purge_replicas=True)
                print(f'  ✓ Deleted rule {rid} ({scope}:{name} -> {rule[\"rse_expression\"]})')
                deleted += 1
            except RucioException as e:
                print(f'  ⚠ Could not delete rule {rid}: {e}')

print(f'  {deleted} rule(s) deleted')
"

    echo "=== Draining deletions via judge-cleaner + reaper ==="
    echo "  purge_replicas=True above marks locks for immediate deletion;"
    echo "  these daemon passes actually remove the physical files."
    for _ in 1 2 3; do
        _exec rucio-server rucio-judge-cleaner --run-once || true
        _exec rucio-server rucio-reaper --run-once --greedy || true
    done
}

# ── RSE distance cleanup ──────────────────────────────────────────

delete_rse_distances() {
    echo "=== Deleting RSE distances ==="
    local pairs=(
        "XRD3 XRD4" "XRD4 XRD3"
        "TEAPOT1 TEAPOT2" "TEAPOT2 TEAPOT1"
        "XRD3 TEAPOT1" "TEAPOT1 XRD3"
        "COPERNICUS_S3 TEAPOT2" "COPERNICUS_S3 XRD4"
    )
    for pair in "${pairs[@]}"; do
        read -r src dst <<< "$pair"
        ra rse delete-distance "$src" "$dst" 2>/dev/null \
            && echo "  ✓ Deleted distance $src -> $dst" \
            || echo "  (no distance $src -> $dst, or already gone)"
    done
}

# ── RSE hard deletion ──────────────────────────────────────────────

delete_rses() {
    echo "=== Hard-deleting RSEs: ${ALL_RSES[*]} ==="
    _exec rucio-server env \
        RSE_NAMES="$(IFS=,; echo "${ALL_RSES[*]}")" \
        python3 -c "
import os
from sqlalchemy import text
from rucio.db.sqla.session import get_session

session = get_session()
names = [n for n in os.environ['RSE_NAMES'].split(',') if n]

# (table, column referencing rse_id) — tried in order, each independently
CHILD_TABLES = [
    ('rse_protocols', 'rse_id'),
    ('rse_attr_map', 'rse_id'),
    ('rse_limits', 'rse_id'),
    ('rse_usage', 'rse_id'),
    ('rse_usage_history', 'rse_id'),
    ('rse_transfer_limits', 'rse_id'),
    ('account_limits', 'rse_id'),
    ('account_usage', 'rse_id'),
    ('distances', 'src_rse_id'),
    ('distances', 'dest_rse_id'),
]

for name in names:
    row = session.execute(
        text('SELECT id FROM rses WHERE rse = :name'), {'name': name}
    ).fetchone()
    if not row:
        print(f'  (RSE {name} not found — already gone)')
        continue
    rse_id = row[0]

    for table, col in CHILD_TABLES:
        try:
            session.execute(
                text(f'DELETE FROM {table} WHERE {col} = :rse_id'),
                {'rse_id': rse_id},
            )
            session.commit()
        except Exception as e:
            session.rollback()
            # Table/column not present in this Rucio version, or nothing
            # to delete there — not fatal, keep going.
            print(f'    (skipped {table}.{col}: {e.__class__.__name__})')

    try:
        session.execute(text('DELETE FROM rses WHERE id = :rse_id'), {'rse_id': rse_id})
        session.commit()
        print(f'  ✓ Deleted RSE {name}')
    except Exception as e:
        session.rollback()
        print(f'  ⚠ Could not delete RSE {name} (row still referenced somewhere): {e}')
"
}

# ── Main ────────────────────────────────────────────────────────

restart_rucio_server() {
    echo "=== Restarting rucio-server to flush its stale RSE-id cache ==="
    docker compose -f docker-compose.yml restart rucio-server
}

main() {
    delete_test_rules_and_replicas
    delete_rse_distances
    delete_rses
    restart_rucio_server
    echo -e "\n=== Teardown complete — re-run 'make init' to fully recreate the testbed ==="
}

main
