"""OPA as a Policy Decision Point.

Everything OPA-specific lives here. The core sees only Outcomes.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from authz_service.adapters.pdp.opa import translate
from authz_service.core.model import Evaluation, Outcome

log = logging.getLogger(__name__)


class OpaPolicyDecisionPoint:
    """Implements the PolicyDecisionPoint port against OPA's data API."""

    def __init__(self, url: str, policy_path: str, timeout_seconds: float) -> None:
        self._policy_path = policy_path.strip("/")
        # No retries: the PEP's own timeout is the budget, and a retry would
        # spend it twice (design-006).
        self._client = httpx.AsyncClient(base_url=url.rstrip("/"), timeout=timeout_seconds)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def evaluate(self, evaluation: Evaluation) -> Outcome:
        try:
            input_doc = translate.to_opa_input(evaluation)
        except ValueError:
            log.warning("no OPA input mapping for action=%s", evaluation.operation)
            return Outcome.NOT_APPLICABLE

        try:
            response = await self._client.post(
                f"/v1/data/{self._policy_path}", json={"input": input_doc}
            )
        except httpx.HTTPError as exc:
            log.warning("PDP evaluate unreachable for action=%s: %s", evaluation.operation, exc)
            return Outcome.INDETERMINATE

        try:
            body = response.json()
        except ValueError:
            log.warning("PDP evaluate returned non-JSON for action=%s", evaluation.operation)
            return Outcome.INDETERMINATE

        return translate.outcome_from_response(response.status_code, body)

    async def is_available(self) -> bool:
        try:
            response = await self._client.get("/health")
        except httpx.HTTPError as exc:
            log.warning("PDP unreachable: %s", exc)
            return False
        return response.status_code == 200

    async def policy_revision(self) -> str | None:
        meta = await self._data("vo/meta")
        if isinstance(meta, dict):
            revision = meta.get("revision")
            if isinstance(revision, str):
                return revision
        return None

    async def known_actions(self) -> frozenset[str]:
        package = self._policy_path.rsplit("/", 1)[0]
        actions = await self._data(f"{package}/_all_known_actions")
        if isinstance(actions, list):
            return frozenset(str(action) for action in actions)
        return frozenset()

    async def _data(self, path: str) -> Any:
        """Read a data path. Returns None when it is undefined or unreachable."""
        try:
            response = await self._client.get(f"/v1/data/{path}")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("PDP data read failed for %s: %s", path, exc)
            return None
        body: dict[str, Any] = response.json()
        # OPA answers {} when the path is undefined.
        return body.get("result")
