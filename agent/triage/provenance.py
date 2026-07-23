"""Small deterministic helpers for incident event provenance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


#: Surrounding words only. The counts themselves are deterministic facts and
#: are rendered identically in every language.
_PROVENANCE_LABELS = {
    "en": {
        "template": (
            "{total} ({current} this run, {prior} from {jobs} earlier {job_word})"
        ),
        "job": "job",
        "jobs": "jobs",
    },
    "tr": {
        "template": (
            "{total} ({current} bu çalıştırmada, {prior} olay {jobs} "
            "{job_word} işten)"
        ),
        "job": "önceki",
        "jobs": "önceki",
    },
}


def format_event_provenance(
    total_events: int,
    metrics: Mapping[str, Any],
    lang: str = "en",
) -> str:
    """Render cross-job event provenance without exposing job identifiers.

    The numbers are identical in every language; only the words around them
    change, so a Turkish report never shows "this run" or "from earlier jobs".
    """
    contributing_jobs = int(metrics.get("contributing_job_count", 0) or 0)
    current_events = int(metrics.get("current_job_event_count", 0) or 0)
    prior_events = int(metrics.get("prior_job_event_count", 0) or 0)
    if contributing_jobs <= 1 or prior_events <= 0:
        return str(total_events)

    prior_jobs = max(1, contributing_jobs - 1)
    labels = _PROVENANCE_LABELS.get(lang, _PROVENANCE_LABELS["en"])
    job_word = labels["job"] if prior_jobs == 1 else labels["jobs"]
    return labels["template"].format(
        total=total_events,
        current=current_events,
        prior=prior_events,
        jobs=prior_jobs,
        job_word=job_word,
    )
