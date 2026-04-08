"""
Phase 3 — unit tests for opa_client.py and permission.py

Mirrors test_phase2_opa.py in structure. Covers:
  - OPA client fail-closed behaviour (unchanged from Phase 2)
  - _build_input: new passthrough keys (scheme, attachments, rule_id)
  - has_permission: OPA response propagation
"""

import json
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from rucio_opa_v2_policy.opa_client import query_opa
from rucio_opa_v2_policy.permission import _build_input, has_permission


def _mock_opa_response(result: bool):
    body = json.dumps({"result": result}).encode()
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read = MagicMock(return_value=body)
    return mock_resp


# ---------------------------------------------------------------------------
# OPA client — fail-closed behaviour (same as Phase 2)
# ---------------------------------------------------------------------------


class TestOpaClient:
    def test_returns_true_when_opa_allows(self):
        with patch("rucio_opa_v2_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(True)
            assert query_opa({"action": "add_rule"}) is True

    def test_returns_false_when_opa_denies(self):
        with patch("rucio_opa_v2_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(False)
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_connection_error(self):
        with patch("rucio_opa_v2_policy.opa_client.urlopen", side_effect=URLError("refused")):
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_timeout(self):
        with patch("rucio_opa_v2_policy.opa_client.urlopen", side_effect=TimeoutError()):
            assert query_opa({"action": "add_rule"}) is False

    def test_fail_closed_on_unexpected_exception(self):
        with patch("rucio_opa_v2_policy.opa_client.urlopen", side_effect=RuntimeError("boom")):
            assert query_opa({"anything": True}) is False

    def test_correct_json_sent_to_opa(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["data"] = json.loads(req.data)
            return _mock_opa_response(True)

        with patch("rucio_opa_v2_policy.opa_client.urlopen", side_effect=fake_urlopen):
            query_opa({"action": "attach_dids_to_dids", "issuer": "alice"})

        assert "input" in captured["data"]
        assert captured["data"]["input"]["action"] == "attach_dids_to_dids"

    def test_default_policy_path_is_v2(self, monkeypatch):
        monkeypatch.delenv("OPA_POLICY_PATH", raising=False)
        monkeypatch.delenv("OPA_URL", raising=False)
        with patch("rucio_opa_v2_policy.opa_client.urlopen") as mock_open:
            mock_open.return_value = _mock_opa_response(True)
            query_opa({})
            called_url = mock_open.call_args[0][0].full_url
        assert "vo/authz/v2/allow" in called_url


# ---------------------------------------------------------------------------
# _build_input — new passthrough keys for Phase 3 actions
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
        doc = _build_input(regular_account, "add_rule", {})
        assert doc["is_admin"] is False

    def test_scheme_forwarded_for_add_protocol(self, root):
        """scheme is a Phase 3 addition to _PASSTHROUGH_KEYS."""
        kw = {"scheme": "davs", "hostname": "xrootd.cern.ch"}
        doc = _build_input(root, "add_protocol", kw)
        assert doc["kwargs"]["scheme"] == "davs"
        assert doc["kwargs"]["hostname"] == "xrootd.cern.ch"

    def test_attachments_forwarded_for_attach_dids_to_dids(self, root):
        """attachments is a Phase 3 addition to _PASSTHROUGH_KEYS."""
        attachments = [{"scope": "alice", "name": "raw", "dids": []}]
        kw = {"scope": "alice", "attachments": attachments}
        doc = _build_input(root, "attach_dids_to_dids", kw)
        assert doc["kwargs"]["attachments"] == attachments

    def test_rule_id_forwarded_for_del_rule(self, regular_account):
        """rule_id is a Phase 3 addition to _PASSTHROUGH_KEYS."""
        kw = {"account": regular_account, "rule_id": "abc-123"}
        doc = _build_input(regular_account, "del_rule", kw)
        assert doc["kwargs"]["rule_id"] == "abc-123"
        # account is an InternalAccount — should be stringified
        assert doc["kwargs"]["account"] == "alice"

    def test_session_never_forwarded(self, root):
        kw = {"session": object(), "scheme": "davs"}
        doc = _build_input(root, "add_protocol", kw)
        assert "session" not in doc["kwargs"]

    def test_action_forwarded(self, root):
        doc = _build_input(root, "attach_dids_to_dids", {})
        assert doc["action"] == "attach_dids_to_dids"


# ---------------------------------------------------------------------------
# has_permission — OPA response drives the result (same pattern as Phase 2)
# ---------------------------------------------------------------------------


class TestPhase3HasPermission:
    def test_opa_allow_propagated(self, root):
        with patch("rucio_opa_v2_policy.permission.query_opa", return_value=True):
            assert has_permission(root, "attach_dids_to_dids", {}) is True

    def test_opa_deny_propagated(self, root):
        with patch("rucio_opa_v2_policy.permission.query_opa", return_value=False):
            assert has_permission(root, "attach_dids_to_dids", {}) is False

    def test_correct_input_forwarded_for_del_rule(self, regular_account):
        captured = {}

        def fake_query(input_doc):
            captured["input"] = input_doc
            return True

        with patch("rucio_opa_v2_policy.permission.query_opa", side_effect=fake_query):
            has_permission(regular_account, "del_rule", {"account": regular_account})

        assert captured["input"]["action"] == "del_rule"
        assert captured["input"]["kwargs"]["account"] == "alice"

    def test_correct_input_forwarded_for_add_protocol(self, root):
        captured = {}

        def fake_query(input_doc):
            captured["input"] = input_doc
            return True

        with patch("rucio_opa_v2_policy.permission.query_opa", side_effect=fake_query):
            has_permission(root, "add_protocol", {"scheme": "davs"})

        assert captured["input"]["action"] == "add_protocol"
        assert captured["input"]["kwargs"]["scheme"] == "davs"
        assert captured["input"]["is_root"] is True
