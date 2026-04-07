"""
Tests for phase2-opa

opa_client.py  — HTTP is mocked; tests verify input construction and
                 fail-closed behaviour on connection errors.

permission.py  — verifies the input document forwarded to OPA is correct,
                 including the is_admin field.
"""

import json
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import rucio.core.account as ra

from rucio_opa_policy.opa_client import query_opa
from rucio_opa_policy.permission import _build_input, has_permission

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_opa_response(result: bool):
    """Return a context-manager mock that simulates a successful OPA response."""
    body = json.dumps({"result": result}).encode()
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read = MagicMock(return_value=body)
    return mock_resp


# ---------------------------------------------------------------------------
# opa_client tests
# ---------------------------------------------------------------------------


class TestOpaClient:
    def test_returns_true_when_opa_allows(self):
        with patch("rucio_opa_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(True)
            assert query_opa({"action": "add_rule"}) is True

    def test_returns_false_when_opa_denies(self):
        with patch("rucio_opa_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(False)
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_connection_error(self):
        with patch("rucio_opa_policy.opa_client.urlopen", side_effect=URLError("refused")):
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_timeout(self):
        with patch("rucio_opa_policy.opa_client.urlopen", side_effect=TimeoutError()):
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_unexpected_exception(self):
        with patch("rucio_opa_policy.opa_client.urlopen", side_effect=RuntimeError("boom")):
            assert query_opa({"anything": True}) is False

    def test_correct_json_sent_to_opa(self):
        """Verify that the payload posted to OPA wraps input correctly."""
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["data"] = json.loads(req.data)
            return _mock_opa_response(True)

        with patch("rucio_opa_policy.opa_client.urlopen", side_effect=fake_urlopen):
            query_opa({"action": "add_rse", "issuer": "root"})

        assert "input" in captured["data"]
        assert captured["data"]["input"]["action"] == "add_rse"

    def test_opa_url_from_env(self, monkeypatch):
        monkeypatch.setenv("OPA_URL", "http://opa-server:8181")
        monkeypatch.setenv("OPA_POLICY_PATH", "custom/allow")
        with patch("rucio_opa_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(True)
            query_opa({})
            called_url = mock_open.call_args[0][0].full_url
        assert called_url == "http://opa-server:8181/v1/data/custom/allow"


# ---------------------------------------------------------------------------
# _build_input tests
# ---------------------------------------------------------------------------


class TestBuildInput:
    def test_root_flag_set_for_root(self, root):
        doc = _build_input(root, "add_rule", {})
        assert doc["is_root"] is True
        assert doc["issuer"] == "root"

    def test_root_flag_false_for_regular(self, regular_account):
        doc = _build_input(regular_account, "add_rule", {})
        assert doc["is_root"] is False

    def test_is_admin_false_by_default(self, regular_account):
        """When has_account_attribute returns False, is_admin must be False."""
        doc = _build_input(regular_account, "add_rule", {})
        assert doc["is_admin"] is False

    def test_is_admin_true_when_account_has_attribute(self, regular_account, monkeypatch):
        """When the account has the admin attribute, is_admin must be True."""
        import rucio_opa_policy.permission as p2_perm

        monkeypatch.setattr(p2_perm, "has_account_attribute", lambda **kw: True)
        doc = _build_input(regular_account, "add_rule", {})
        assert doc["is_admin"] is True

    def test_is_admin_not_looked_up_for_root(self, root, monkeypatch):
        """Root is privileged by is_root; no DB call needed for is_admin."""
        called = []
        monkeypatch.setattr(ra, "has_account_attribute", lambda **kw: called.append(1) or False)
        _build_input(root, "add_rule", {})
        assert called == [], "has_account_attribute should not be called for root"

    def test_action_forwarded(self, root):
        doc = _build_input(root, "add_rse", {})
        assert doc["action"] == "add_rse"

    def test_known_kwargs_forwarded(self, root):
        kw = {
            "rse_expression": "CERN_DATADISK",
            "source_protocol": "webdav",
            "dst_protocol": "s3",
            "locked": False,
        }
        doc = _build_input(root, "add_rule", kw)
        assert doc["kwargs"]["rse_expression"] == "CERN_DATADISK"
        assert doc["kwargs"]["source_protocol"] == "webdav"
        assert doc["kwargs"]["dst_protocol"] == "s3"
        assert doc["kwargs"]["locked"] is False

    def test_session_not_forwarded(self, root):
        """SQLAlchemy sessions must never be included in the OPA input."""
        kw = {"session": object(), "rse_expression": "CERN_DATADISK"}
        doc = _build_input(root, "add_rule", kw)
        assert "session" not in doc["kwargs"]

    def test_internal_account_in_account_field_is_stringified(self, root, regular_account):
        """If kwargs['account'] is an InternalAccount, its .external is used."""
        kw = {"account": regular_account}
        doc = _build_input(root, "add_rule", kw)
        assert doc["kwargs"]["account"] == "alice"

    def test_did_kwargs_forwarded(self, root):
        """DID-related kwargs like scope and name are included."""
        kw = {"scope": "atlas", "name": "dataset1"}
        doc = _build_input(root, "add_did", kw)
        assert doc["kwargs"]["scope"] == "atlas"
        assert doc["kwargs"]["name"] == "dataset1"


# ---------------------------------------------------------------------------
# has_permission (Phase 2) integration — OPA response drives the result
# ---------------------------------------------------------------------------


class TestPhase2HasPermission:
    def test_opa_allow_propagated(self, root):
        with patch("rucio_opa_policy.permission.query_opa", return_value=True):
            assert has_permission(root, "add_rule", {}) is True

    def test_opa_deny_propagated(self, root):
        with patch("rucio_opa_policy.permission.query_opa", return_value=False):
            assert has_permission(root, "add_rule", {}) is False

    def test_correct_input_forwarded_to_opa(self, root):
        captured = {}

        def fake_query(input_doc):
            captured["input"] = input_doc
            return True

        with patch("rucio_opa_policy.permission.query_opa", side_effect=fake_query):
            has_permission(root, "add_rse", {"rse": "CERN_DATADISK"})

        assert captured["input"]["action"] == "add_rse"
        assert captured["input"]["is_root"] is True
        assert captured["input"]["kwargs"]["rse"] == "CERN_DATADISK"

    def test_is_admin_included_in_opa_input(self, regular_account, monkeypatch):
        """is_admin from has_account_attribute reaches the OPA input doc."""
        import rucio_opa_policy.permission as p2_perm

        monkeypatch.setattr(p2_perm, "has_account_attribute", lambda **kw: True)
        captured = {}

        def fake_query(input_doc):
            captured["input"] = input_doc
            return True

        with patch("rucio_opa_policy.permission.query_opa", side_effect=fake_query):
            has_permission(regular_account, "del_rse", {})

        assert captured["input"]["is_admin"] is True
