from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Literal, Protocol

from agent.config import Settings


RetentionEntity = Literal[
    "canonical_event",
    "detection_signal",
    "ingestion_job",
    "incident",
    "audit_event",
]


@dataclass(frozen=True)
class RetentionPolicy:
    version: str
    canonical_event_days: int
    detection_signal_days: int
    completed_job_days: int
    terminal_incident_days: int
    audit_event_days: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", self.version):
            raise ValueError("retention_policy_version_invalid")
        day_values = (
            self.canonical_event_days,
            self.detection_signal_days,
            self.completed_job_days,
            self.terminal_incident_days,
            self.audit_event_days,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
            or value > 36_500
            for value in day_values
        ):
            raise ValueError("retention_policy_days_invalid")

    @classmethod
    def from_settings(cls, settings: Settings) -> RetentionPolicy:
        return cls(
            version=settings.retention_policy_version,
            canonical_event_days=settings.retention_canonical_event_days,
            detection_signal_days=settings.retention_detection_signal_days,
            completed_job_days=settings.retention_completed_job_days,
            terminal_incident_days=settings.retention_terminal_incident_days,
            audit_event_days=settings.retention_audit_event_days,
        )


@dataclass(frozen=True)
class RetentionCutoffs:
    canonical_event: datetime
    detection_signal: datetime
    ingestion_job: datetime
    incident: datetime
    audit_event: datetime


@dataclass(frozen=True)
class RetentionCandidateSummary:
    entity_type: RetentionEntity
    cutoff: datetime
    candidate_count: int
    oldest_candidate_at: datetime | None
    newest_candidate_at: datetime | None
    protected_by_active_relationship_count: int
    protected_by_legal_hold_count: int


@dataclass(frozen=True)
class RetentionPlan:
    policy_version: str
    generated_at: datetime
    cutoffs: RetentionCutoffs
    candidates: tuple[RetentionCandidateSummary, ...]

    @property
    def total_candidate_count(self) -> int:
        return sum(summary.candidate_count for summary in self.candidates)


class RetentionPlanningRepository(Protocol):
    def summarize(
        self,
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> tuple[RetentionCandidateSummary, ...]: ...


class RetentionPlanner:
    def __init__(
        self,
        repository: RetentionPlanningRepository,
        policy: RetentionPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def plan(self) -> RetentionPlan:
        generated_at = self._clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        generated_at = generated_at.astimezone(timezone.utc)
        cutoffs = RetentionCutoffs(
            canonical_event=generated_at
            - timedelta(days=self._policy.canonical_event_days),
            detection_signal=generated_at
            - timedelta(days=self._policy.detection_signal_days),
            ingestion_job=generated_at
            - timedelta(days=self._policy.completed_job_days),
            incident=generated_at
            - timedelta(days=self._policy.terminal_incident_days),
            audit_event=generated_at
            - timedelta(days=self._policy.audit_event_days),
        )
        return RetentionPlan(
            policy_version=self._policy.version,
            generated_at=generated_at,
            cutoffs=cutoffs,
            candidates=self._repository.summarize(
                cutoffs=cutoffs,
                as_of=generated_at,
            ),
        )
