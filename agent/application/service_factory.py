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

import hashlib
from typing import Optional

from agent.application.analysis_service import AnalysisService
from agent.config import Settings, get_settings
from agent.persistence.unit_of_work import UnitOfWork

_SHA256_CHUNK_BYTES = 1024 * 1024


def build_persistent_analysis_service(
    settings: Optional[Settings] = None,
) -> AnalysisService:
    """Construct an AnalysisService backed by the configured database."""
    settings = settings or get_settings()
    return AnalysisService(uow=UnitOfWork(settings=settings))


def compute_file_sha256(file_path: str) -> str:
    """Streaming SHA-256 of a file, matching the staging store's digest so a
    CLI run and an API upload of the same bytes share one idempotency key."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_SHA256_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_idempotency_key(
    file_sha256: str, pipeline_version: str, analysis_mode: str
) -> str:
    """The existing idempotency-key format: sha256 of
    ``{file_sha256}:{pipeline_version}:{analysis_mode}`` (see
    BackgroundAnalysisService.submit_file)."""
    idemp_string = f"{file_sha256}:{pipeline_version}:{analysis_mode}"
    return hashlib.sha256(idemp_string.encode("utf-8")).hexdigest()
