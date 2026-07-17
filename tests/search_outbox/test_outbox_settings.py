from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent.config import Settings


def test_outbox_claim_and_batch_settings_are_typed_and_bounded() -> None:
    settings = Settings(_env_file=None)

    assert settings.opensearch_outbox_enqueue_chunk_size == 250
    assert settings.opensearch_outbox_claim_batch_size == 100
    assert settings.opensearch_outbox_lease_seconds == 300
    assert settings.opensearch_outbox_max_claim_batch_size == 1_000


def test_claim_batch_default_cannot_exceed_configured_maximum() -> None:
    with pytest.raises(
        ValidationError,
        match="opensearch_outbox_claim_batch_size_exceeds_maximum",
    ):
        Settings(
            _env_file=None,
            opensearch_outbox_claim_batch_size=101,
            opensearch_outbox_max_claim_batch_size=100,
        )
