"""The single batch brief-enrichment stage of the analyze pipeline.

Runs once per analyze job, after final canonical incidents exist, their
deterministic dispositions are computed, presentation groups are built and the
ACT NOW / INVESTIGATE rows are selected. Exactly the same code serves the CLI,
the synchronous API and background analysis, so provider-call semantics cannot
drift between entry points.

Logical provider invocations for one fresh analyze job:

===================================== ==========================
condition                             logical invocations
===================================== ==========================
LLM disabled                          0
no selected rows                      0
rows selected and provider available  1
malformed / timeout / circuit open    1 attempted, then fallback
completed-job replay                  0
ingest or detect mode                 0
===================================== ==========================

Transport retries inside one invocation are counted separately and never
inflate the logical count.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Optional

from agent.detection.presentation import BriefActionItem
from agent.triage.enrichment import (
    BriefEnrichmentResult,
    build_enrichment_request,
    complete_with_fallback,
    deterministic_fallback,
    validate_enrichment_payload,
)
from agent.triage.enrichment_prompt import build_enrichment_system_prompt
from agent.triage.provider import BriefEnrichmentProviderRequest


logger = logging.getLogger(__name__)


def enrich_brief_items(
    items: Sequence[BriefActionItem],
    *,
    llm_enabled: bool,
    provider_builder: Optional[object] = None,
    timeout_seconds: Optional[float] = None,
) -> BriefEnrichmentResult:
    """Produce the bilingual enrichment for the selected brief rows.

    Always returns a complete result: every requested row gets text, from the
    provider when it answered acceptably and from the deterministic fallback
    otherwise. A provider failure is recorded as a bounded reason string and
    never changes any incident's verdict, severity or counts.
    """
    if not items:
        return BriefEnrichmentResult(items=(), provider_invocation_count=0)

    if not llm_enabled:
        return BriefEnrichmentResult(
            items=tuple(deterministic_fallback(item) for item in items),
            provider_invocation_count=0,
            enrichment_failure_reason="llm_disabled",
        )

    if provider_builder is None:
        from agent.triage.provider_factory import build_provider

        provider_builder = build_provider

    request = build_enrichment_request(items)
    requested = items[: len(request.items)]

    try:
        provider = provider_builder()  # type: ignore[operator]
    except Exception as exc:
        logger.warning(
            "Brief enrichment provider unavailable",
            extra={"error": type(exc).__name__},
        )
        return BriefEnrichmentResult(
            items=tuple(deterministic_fallback(item) for item in items),
            provider_invocation_count=0,
            enrichment_failure_reason="provider_unavailable",
        )

    deadline = None
    if timeout_seconds is not None:
        import time

        deadline = time.monotonic() + timeout_seconds

    provider_request = BriefEnrichmentProviderRequest(
        system_prompt=build_enrichment_system_prompt(),
        payload=request.model_dump_json(),
        item_ids=[item.item_id for item in requested],
        deadline=deadline,
    )

    # From here on exactly one logical invocation has been attempted, whatever
    # happens to it.
    try:
        response = provider.invoke_brief_enrichment(provider_request)
    except Exception as exc:
        logger.warning(
            "Brief enrichment call failed; rendering deterministic text",
            extra={"error": type(exc).__name__},
        )
        return BriefEnrichmentResult(
            items=tuple(deterministic_fallback(item) for item in items),
            provider_invocation_count=1,
            enrichment_failure_reason=type(exc).__name__,
        )

    accepted, rejected = validate_enrichment_payload(response.raw_payload, requested)
    completed = complete_with_fallback(accepted, items)

    failure_reason = None
    if rejected:
        # Bounded, non-identifying summary of why some rows fell back.
        reasons = sorted({reason for reason in rejected.values()})
        failure_reason = ",".join(reasons)[:200]

    return BriefEnrichmentResult(
        items=completed,
        provider_invocation_count=1,
        provider_retry_count=getattr(response, "retry_count", 0),
        enrichment_failure_reason=failure_reason,
    )
