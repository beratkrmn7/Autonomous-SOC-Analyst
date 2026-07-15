import datetime
import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

from agent.application.staging import FileStagingStore
from agent.persistence.orm_models import AuditEvent, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)

USER_REQUESTED = "user_requested"


def _as_datetime(value: object) -> datetime.datetime | None:
    return value if isinstance(value, datetime.datetime) else None


class JobCancellationRequested(Exception):
    """Raised at a safe checkpoint when database cancellation is requested."""

    def __init__(self, job_id: str):
        super().__init__("job_cancellation_requested")
        self.job_id = job_id


class JobCancellationChecker(Protocol):
    def raise_if_cancelled(self, job_id: str) -> None:
        """Raise when the database says cooperative cancellation is pending."""
        ...


class DatabaseJobCancellationChecker:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def raise_if_cancelled(self, job_id: str) -> None:
        session = self.session_factory()
        try:
            status = (
                session.query(IngestionJob.status)
                .filter(IngestionJob.id == job_id)
                .scalar()
            )
            if status in ("cancel_requested", "cancelled"):
                raise JobCancellationRequested(job_id)
        finally:
            session.close()


class JobNotFoundError(Exception):
    pass


class JobNotCancellableError(Exception):
    def __init__(self, status: str):
        super().__init__("job_not_cancellable")
        self.status = status


@dataclass(frozen=True)
class JobCancellationResult:
    job_id: str
    status: str
    cancel_requested_at: datetime.datetime | None
    cancelled_at: datetime.datetime | None


class JobCancellationService:
    """Owns atomic, database-backed job cancellation transitions."""

    def __init__(self, uow: UnitOfWork, staging_store: FileStagingStore):
        self.uow = uow
        self.staging_store = staging_store

    @staticmethod
    def _add_audit_event(
        session,
        *,
        job_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        timestamp: datetime.datetime,
    ) -> None:
        existing = session.query(AuditEvent.id).filter(
            AuditEvent.event_type == event_type,
            AuditEvent.entity_type == "ingestion_job",
            AuditEvent.entity_id == job_id,
        ).first()
        if existing:
            return

        session.add(AuditEvent(
            audit_event_id=f"ae_{uuid.uuid4().hex}",
            timestamp=timestamp,
            event_type=event_type,
            entity_type="ingestion_job",
            entity_id=job_id,
            action=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            actor=actor_type,
            details={"cancel_reason_code": USER_REQUESTED},
        ))

    def _cleanup_staging(self, job_id: str) -> None:
        try:
            self.staging_store.remove_file(job_id)
        except Exception:
            logger.warning("staging_cleanup_failed")

    def cancel(
        self,
        job_id: str,
        *,
        actor_type: str = "system",
        actor_id: str = "cancellation_service",
    ) -> JobCancellationResult:
        now = datetime.datetime.now(datetime.timezone.utc)
        cleanup_staging = False

        with self.uow:
            assert self.uow.session is not None
            session = self.uow.session

            queued_update = session.query(IngestionJob).filter(
                IngestionJob.id == job_id,
                IngestionJob.status == "queued",
            ).update({
                "status": "cancelled",
                "cancel_requested_at": now,
                "cancelled_at": now,
                "cancel_reason_code": USER_REQUESTED,
                "cancel_requested_by": actor_id,
                "worker_id": None,
                "next_retry_at": None,
                "lease_expires_at": None,
            }, synchronize_session=False)

            if queued_update:
                self._add_audit_event(
                    session,
                    job_id=job_id,
                    event_type="job_cancellation_requested",
                    actor_type=actor_type,
                    actor_id=actor_id,
                    timestamp=now,
                )
                self._add_audit_event(
                    session,
                    job_id=job_id,
                    event_type="job_cancelled",
                    actor_type="system",
                    actor_id="cancellation_service",
                    timestamp=now,
                )
                session.commit()
                cleanup_staging = True
                result = JobCancellationResult(job_id, "cancelled", now, now)
            else:
                session.rollback()
                processing_update = session.query(IngestionJob).filter(
                    IngestionJob.id == job_id,
                    IngestionJob.status == "processing",
                ).update({
                    "status": "cancel_requested",
                    "cancel_requested_at": now,
                    "cancel_reason_code": USER_REQUESTED,
                    "cancel_requested_by": actor_id,
                }, synchronize_session=False)

                if processing_update:
                    self._add_audit_event(
                        session,
                        job_id=job_id,
                        event_type="job_cancellation_requested",
                        actor_type=actor_type,
                        actor_id=actor_id,
                        timestamp=now,
                    )
                    session.commit()
                    result = JobCancellationResult(
                        job_id, "cancel_requested", now, None
                    )
                else:
                    session.rollback()
                    job = session.get(IngestionJob, job_id)
                    if job is None:
                        raise JobNotFoundError(job_id)
                    status = str(job.status)
                    if status in ("completed", "failed"):
                        raise JobNotCancellableError(status)
                    if status not in ("cancel_requested", "cancelled"):
                        raise JobNotCancellableError(status)
                    result = JobCancellationResult(
                        job_id=job_id,
                        status=status,
                        cancel_requested_at=_as_datetime(job.cancel_requested_at),
                        cancelled_at=_as_datetime(job.cancelled_at),
                    )

        if cleanup_staging:
            self._cleanup_staging(job_id)
        return result

    def finalize(self, job_id: str) -> JobCancellationResult:
        """Finish a cooperative cancellation in a new safe transaction."""
        now = datetime.datetime.now(datetime.timezone.utc)
        cleanup_staging = False

        with self.uow:
            assert self.uow.session is not None
            session = self.uow.session
            updated = session.query(IngestionJob).filter(
                IngestionJob.id == job_id,
                IngestionJob.status == "cancel_requested",
            ).update({
                "status": "cancelled",
                "cancelled_at": now,
                "worker_id": None,
                "next_retry_at": None,
                "lease_expires_at": None,
            }, synchronize_session=False)

            if updated:
                self._add_audit_event(
                    session,
                    job_id=job_id,
                    event_type="job_cancelled",
                    actor_type="system",
                    actor_id="analysis_worker",
                    timestamp=now,
                )
                session.commit()
                cleanup_staging = True
                job = session.get(IngestionJob, job_id)
                requested_at = (
                    _as_datetime(job.cancel_requested_at) if job else None
                )
                result = JobCancellationResult(
                    job_id, "cancelled", requested_at, now
                )
            else:
                session.rollback()
                job = session.get(IngestionJob, job_id)
                if job is None:
                    raise JobNotFoundError(job_id)
                result = JobCancellationResult(
                    job_id=job_id,
                    status=str(job.status),
                    cancel_requested_at=_as_datetime(job.cancel_requested_at),
                    cancelled_at=_as_datetime(job.cancelled_at),
                )

        if cleanup_staging:
            self._cleanup_staging(job_id)
        return result
