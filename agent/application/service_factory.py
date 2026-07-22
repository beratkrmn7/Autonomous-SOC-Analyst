"""Application-level factory for persistent AnalysisService usage.

The CLI, like the API and the background worker, must run analysis against the
configured database so that jobs, canonical events, current-job signals, final
incidents, and (in analyze mode) triage/report outputs are persisted - and so
that optional stateful cross-job correlation can converge activity across
separate invocations. This module wires an AnalysisService to the configured
Settings and a UnitOfWork without duplicating any database-initialization
logic (UnitOfWork builds the engine/session factory from Settings).

It runs no migrations. The database schema is expected to already exist, exactly
as it is for the API and worker entry points.
"""

from __future__ import annotations

from typing import Optional

from agent.application.analysis_service import AnalysisService
from agent.application.idempotency import (  # re-exported for callers of this factory
    compute_file_sha256,
    compute_idempotency_key,
)
from agent.config import Settings, get_settings
from agent.persistence.unit_of_work import UnitOfWork

__all__ = [
    "build_persistent_analysis_service",
    "compute_file_sha256",
    "compute_idempotency_key",
]


def build_persistent_analysis_service(
    settings: Optional[Settings] = None,
) -> AnalysisService:
    """Construct an AnalysisService backed by the configured database."""
    settings = settings or get_settings()
    return AnalysisService(uow=UnitOfWork(settings=settings))
