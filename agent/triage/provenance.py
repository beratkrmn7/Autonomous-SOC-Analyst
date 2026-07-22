"""Small deterministic helpers for incident event provenance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def format_event_provenance(total_events: int, metrics: Mapping[str, Any]) -> str:
    """Render cross-job event provenance without exposing job identifiers."""
    contributing_jobs = int(metrics.get("contributing_job_count", 0) or 0)
    current_events = int(metrics.get("current_job_event_count", 0) or 0)
    prior_events = int(metrics.get("prior_job_event_count", 0) or 0)
    if contributing_jobs <= 1 or prior_events <= 0:
        return str(total_events)
    prior_jobs = max(1, contributing_jobs - 1)
    job_word = "job" if prior_jobs == 1 else "jobs"
    return (
        f"{total_events} ({current_events} this run, {prior_events} from "
        f"{prior_jobs} earlier {job_word})"
    )
