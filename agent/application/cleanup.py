from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, cast
import re
import uuid

from sqlalchemy.exc import IntegrityError

from agent.application.retention import RetentionEntity, RetentionPolicy
from agent.archive.index import ArchiveMembershipIndex
from agent.archive.io import (
    ArchiveIntegrityError,
    ArchiveStabilitySnapshot,
    ArchiveVerificationResult,
    ArchiveVerifier,
)
from agent.archive.schemas import validate_archive_id, utc_datetime
from agent.archive.storage import ArchiveStorageError, ArchiveStore
from agent.config import Settings
from agent.persistence.cleanup_repository import (
    CleanupBatchCounts,
    CleanupPersistenceError,
    RetentionCleanupRepository,
)
from agent.persistence.orm_models import (
    AuditEvent,
    RetentionCleanupProgress,
    RetentionCleanupRun,
)
from agent.persistence.unit_of_work import UnitOfWork


CLEANUP_ENTITY_ORDER: tuple[RetentionEntity, ...] = (
    "incident",
    "ingestion_job",
    "audit_event",
    "detection_signal",
    "canonical_event",
)
_CLEANUP_RUN_ID_PATTERN = re.compile(r"^CLN-[0-9a-f]{32}$")
CleanupRunStatus = Literal["pending", "running", "completed", "failed"]
CleanupProgressStatus = Literal["pending", "running", "completed"]
MAX_DEPENDENCIES_PER_ROOT = 5_000


class CleanupOperationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CleanupOperationResult:
    cleanup_run_id: str
    archive_id: str
    status: CleanupRunStatus
    deleted_record_count: int
    protected_record_count: int
    missing_record_count: int
    skipped_record_count: int
    completed_entity_phases: tuple[RetentionEntity, ...]
    resumed: bool


class RetentionCleanupService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        store: ArchiveStore,
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
        worker_id_factory: Callable[[], str] | None = None,
        cleanup_run_id_factory: Callable[[], str] | None = None,
        batch_committed_hook: Callable[[int], None] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._store = store
        self._settings = settings
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._worker_id_factory = worker_id_factory or (lambda: uuid.uuid4().hex)
        self._cleanup_run_id_factory = cleanup_run_id_factory or (
            lambda: f"CLN-{uuid.uuid4().hex}"
        )
        self._batch_committed_hook = batch_committed_hook
        self._verifier = ArchiveVerifier(store)

    def execute(self, archive_id: str) -> CleanupOperationResult:
        validate_archive_id(archive_id)
        policy = RetentionPolicy.from_settings(self._settings)
        verification = self._verify_gate(archive_id, policy)
        snapshot = ArchiveStabilitySnapshot.from_verification(verification)
        worker_id = self._worker_id_factory()
        if not re.fullmatch(r"[0-9a-f]{32}", worker_id):
            raise CleanupOperationError("cleanup_worker_id_invalid")

        try:
            membership_index = ArchiveMembershipIndex.build(
                self._store,
                archive_id,
                verification.manifest,
                temporary_root=self._settings.retention_archive_root,
            )
        except Exception as exc:
            raise CleanupOperationError(self._error_code(exc)) from None
        with membership_index as membership:
            try:
                post_index_verification = self._verifier.verify(archive_id)
            except Exception as exc:
                raise CleanupOperationError(self._error_code(exc)) from None
            if (
                ArchiveStabilitySnapshot.from_verification(post_index_verification)
                != snapshot
            ):
                raise CleanupOperationError("cleanup_archive_integrity_failed")
            cleanup_run_id, resumed, completed = self._prepare_and_claim(
                verification,
                snapshot,
                worker_id,
            )
            if completed:
                return self._result(cleanup_run_id, resumed=False)
            try:
                self._execute_phases(
                    cleanup_run_id,
                    archive_id,
                    worker_id,
                    snapshot,
                    membership,
                    policy,
                )
                self._complete(cleanup_run_id, worker_id, archive_id, snapshot)
                return self._result(cleanup_run_id, resumed=resumed)
            except Exception as exc:
                error_code = self._error_code(exc)
                self._mark_failed(cleanup_run_id, worker_id, error_code)
                raise CleanupOperationError(error_code) from None

    def _verify_gate(
        self,
        archive_id: str,
        policy: RetentionPolicy,
    ) -> ArchiveVerificationResult:
        try:
            with self._uow_factory() as uow:
                run = uow.archive_runs.get(archive_id)
                if run is None:
                    raise CleanupOperationError("cleanup_archive_not_found")
                if str(run.status) != "verified":
                    raise CleanupOperationError("cleanup_archive_not_verified")
                if str(run.storage_key) != archive_id:
                    raise CleanupOperationError("cleanup_archive_storage_key_invalid")
                known_checksum = str(run.manifest_sha256 or "")
                archive_policy_version = str(run.policy_version)
                archive_schema_version = str(run.schema_version)
                archive_as_of = utc_datetime(cast(datetime, run.archive_as_of))
                candidate_count = int(run.candidate_record_count)
                dependency_count = int(run.dependency_record_count)
                total_count = int(run.total_record_count)
            verification = self._verifier.verify(archive_id)
            manifest = verification.manifest
            if verification.manifest_sha256 != known_checksum:
                raise ArchiveIntegrityError("archive_manifest_checksum_mismatch")
            if (
                archive_schema_version
                != self._settings.retention_archive_schema_version
                or archive_policy_version != policy.version
                or manifest.policy_version != archive_policy_version
                or utc_datetime(manifest.archive_as_of) != archive_as_of
                or candidate_count != manifest.candidate_record_count
                or dependency_count != manifest.dependency_record_count
                or total_count != manifest.total_record_count
            ):
                raise ArchiveIntegrityError("archive_database_metadata_mismatch")
            return verification
        except CleanupOperationError:
            raise
        except Exception as exc:
            raise CleanupOperationError(self._error_code(exc)) from None

    def _prepare_and_claim(
        self,
        verification: ArchiveVerificationResult,
        snapshot: ArchiveStabilitySnapshot,
        worker_id: str,
    ) -> tuple[str, bool, bool]:
        for attempt in range(2):
            try:
                return self._prepare_and_claim_once(
                    verification,
                    snapshot,
                    worker_id,
                )
            except IntegrityError:
                if attempt == 1:
                    raise CleanupOperationError("cleanup_run_conflict") from None
        raise CleanupOperationError("cleanup_run_conflict")

    def _prepare_and_claim_once(
        self,
        verification: ArchiveVerificationResult,
        snapshot: ArchiveStabilitySnapshot,
        worker_id: str,
    ) -> tuple[str, bool, bool]:
        now = utc_datetime(self._clock())
        manifest = verification.manifest
        with self._uow_factory() as uow:
            repository = uow.cleanup
            run = repository.get_by_archive(verification.archive_id)
            created = run is None
            if run is None:
                cleanup_run_id = self._cleanup_run_id_factory()
                if not _CLEANUP_RUN_ID_PATTERN.fullmatch(cleanup_run_id):
                    raise CleanupOperationError("cleanup_run_id_invalid")
                run = RetentionCleanupRun(
                    cleanup_run_id=cleanup_run_id,
                    archive_id=verification.archive_id,
                    status="pending",
                    policy_version=manifest.policy_version,
                    archive_schema_version=self._settings.retention_archive_schema_version,
                    manifest_sha256=verification.manifest_sha256,
                    archive_as_of=manifest.archive_as_of,
                    archive_snapshot=snapshot.to_dict(),
                    updated_at=now,
                    current_phase="pending",
                    current_entity_type=CLEANUP_ENTITY_ORDER[0],
                    attempt_count=0,
                    deleted_record_count=0,
                    protected_record_count=0,
                    missing_record_count=0,
                    skipped_record_count=0,
                    version=1,
                )
                repository.add_run(run)
                for entity_type in CLEANUP_ENTITY_ORDER:
                    repository.add_progress(
                        RetentionCleanupProgress(
                            cleanup_run_id=cleanup_run_id,
                            entity_type=entity_type,
                            status="pending",
                            scanned_count=0,
                            deleted_count=0,
                            protected_count=0,
                            missing_count=0,
                            skipped_count=0,
                        )
                    )
                repository.flush()
            else:
                cleanup_run_id = str(run.cleanup_run_id)
                self._validate_existing_run(run, verification, snapshot)
                if str(run.status) == "completed":
                    return cleanup_run_id, False, True
            previous_status = str(run.status)
            if not repository.claim(
                cleanup_run_id,
                owner=worker_id,
                now=now,
                lease_seconds=self._settings.retention_cleanup_lease_seconds,
            ):
                raise CleanupOperationError("cleanup_lease_active")
            self._add_audit(
                uow,
                event_type=(
                    "retention_cleanup_started"
                    if created
                    else "retention_cleanup_resumed"
                ),
                cleanup_run_id=cleanup_run_id,
                archive_id=verification.archive_id,
                timestamp=now,
                policy_version=manifest.policy_version,
                archive_schema_version=self._settings.retention_archive_schema_version,
                status="running",
            )
            resumed = not created and previous_status in {"pending", "running", "failed"}
            return cleanup_run_id, resumed, False

    @staticmethod
    def _validate_existing_run(
        run: RetentionCleanupRun,
        verification: ArchiveVerificationResult,
        snapshot: ArchiveStabilitySnapshot,
    ) -> None:
        persisted_snapshot = ArchiveStabilitySnapshot.from_dict(run.archive_snapshot)
        if (
            str(run.archive_id) != verification.archive_id
            or str(run.policy_version) != verification.manifest.policy_version
            or str(run.manifest_sha256) != verification.manifest_sha256
            or utc_datetime(cast(datetime, run.archive_as_of))
            != utc_datetime(verification.manifest.archive_as_of)
            or persisted_snapshot != snapshot
        ):
            raise CleanupOperationError("cleanup_run_archive_mismatch")

    def _execute_phases(
        self,
        cleanup_run_id: str,
        archive_id: str,
        worker_id: str,
        snapshot: ArchiveStabilitySnapshot,
        membership: ArchiveMembershipIndex,
        policy: RetentionPolicy,
    ) -> None:
        committed_batches = 0
        for position, entity_type in enumerate(CLEANUP_ENTITY_ORDER):
            next_entity = (
                CLEANUP_ENTITY_ORDER[position + 1]
                if position + 1 < len(CLEANUP_ENTITY_ORDER)
                else None
            )
            while True:
                batch_committed = False
                with self._uow_factory() as uow:
                    repository: RetentionCleanupRepository = uow.cleanup
                    run = repository.get(cleanup_run_id)
                    progress = repository.get_progress(cleanup_run_id, entity_type)
                    if run is None or progress is None:
                        raise CleanupPersistenceError("cleanup_progress_missing")
                    if str(progress.status) == "completed":
                        break
                    self._assert_run_lease(run, worker_id)
                    self._assert_snapshot(run, snapshot)
                    self._verifier.assert_stable(archive_id, snapshot)
                    batch = membership.candidate_batch(
                        entity_type,
                        last_recorded_at=cast(
                            datetime | None,
                            progress.last_recorded_at,
                        ),
                        last_entity_id=cast(str | None, progress.last_entity_id),
                        batch_size=self._settings.retention_cleanup_batch_size,
                    )
                    now = utc_datetime(self._clock())
                    if not batch:
                        repository.complete_progress(
                            cleanup_run_id,
                            entity_type,
                            owner=worker_id,
                            expected_version=int(run.version),
                            now=now,
                            lease_seconds=self._settings.retention_cleanup_lease_seconds,
                            next_entity_type=next_entity,
                        )
                        continue
                    entity_ids = tuple(record.entity_id for record in batch)
                    cutoffs = policy.cutoffs(now)
                    existing, eligible = repository.classify(
                        entity_type,
                        entity_ids,
                        cutoffs=cutoffs,
                        as_of=now,
                    )
                    deleted, dependency_protected = repository.delete_eligible(
                        entity_type,
                        eligible,
                        cutoffs=cutoffs,
                        as_of=now,
                        authorization=membership,
                        dependency_limit=MAX_DEPENDENCIES_PER_ROOT,
                    )
                    missing = len(set(entity_ids) - existing)
                    protected = len(existing - eligible) + dependency_protected
                    counts = CleanupBatchCounts(
                        scanned=len(batch),
                        deleted=deleted,
                        protected=protected,
                        missing=missing,
                    )
                    if counts.deleted + counts.protected + counts.missing != counts.scanned:
                        raise CleanupPersistenceError("cleanup_batch_count_mismatch")
                    finished_at = utc_datetime(self._clock())
                    repository.apply_batch(
                        cleanup_run_id,
                        entity_type,
                        owner=worker_id,
                        expected_version=int(run.version),
                        now=finished_at,
                        lease_seconds=self._settings.retention_cleanup_lease_seconds,
                        counts=counts,
                        last_recorded_at=batch[-1].recorded_at,
                        last_entity_id=batch[-1].entity_id,
                    )
                    batch_committed = True
                if batch_committed:
                    committed_batches += 1
                    if self._batch_committed_hook is not None:
                        self._batch_committed_hook(committed_batches)

    def _complete(
        self,
        cleanup_run_id: str,
        worker_id: str,
        archive_id: str,
        snapshot: ArchiveStabilitySnapshot,
    ) -> None:
        now = utc_datetime(self._clock())
        with self._uow_factory() as uow:
            repository = uow.cleanup
            run = repository.get(cleanup_run_id)
            if run is None:
                raise CleanupPersistenceError("cleanup_run_missing")
            self._assert_run_lease(run, worker_id)
            self._assert_snapshot(run, snapshot)
            self._verifier.assert_stable(archive_id, snapshot)
            for entity_type in CLEANUP_ENTITY_ORDER:
                progress = repository.get_progress(cleanup_run_id, entity_type)
                if progress is None or str(progress.status) != "completed":
                    raise CleanupPersistenceError("cleanup_progress_incomplete")
            repository.complete_run(
                cleanup_run_id,
                owner=worker_id,
                expected_version=int(run.version),
                now=now,
            )
            self._add_audit(
                uow,
                event_type="retention_cleanup_completed",
                cleanup_run_id=cleanup_run_id,
                archive_id=archive_id,
                timestamp=now,
                policy_version=str(run.policy_version),
                archive_schema_version=str(run.archive_schema_version),
                status="completed",
                deleted=int(run.deleted_record_count),
                protected=int(run.protected_record_count),
                missing=int(run.missing_record_count),
                skipped=int(run.skipped_record_count),
            )

    def _mark_failed(
        self,
        cleanup_run_id: str,
        worker_id: str,
        error_code: str,
    ) -> None:
        now = utc_datetime(self._clock())
        try:
            with self._uow_factory() as uow:
                repository = uow.cleanup
                run = repository.get(cleanup_run_id)
                if run is None:
                    return
                if not repository.fail_run(
                    cleanup_run_id,
                    owner=worker_id,
                    now=now,
                    error_code=error_code,
                ):
                    return
                self._add_audit(
                    uow,
                    event_type="retention_cleanup_failed",
                    cleanup_run_id=cleanup_run_id,
                    archive_id=str(run.archive_id),
                    timestamp=now,
                    policy_version=str(run.policy_version),
                    archive_schema_version=str(run.archive_schema_version),
                    status="failed",
                    deleted=int(run.deleted_record_count),
                    protected=int(run.protected_record_count),
                    missing=int(run.missing_record_count),
                    skipped=int(run.skipped_record_count),
                    error_code=error_code,
                )
        except Exception:
            return

    def _result(self, cleanup_run_id: str, *, resumed: bool) -> CleanupOperationResult:
        with self._uow_factory() as uow:
            run = uow.cleanup.get(cleanup_run_id)
            if run is None:
                raise CleanupOperationError("cleanup_run_missing")
            completed_phases = tuple(
                entity_type
                for entity_type in CLEANUP_ENTITY_ORDER
                if (
                    (progress := uow.cleanup.get_progress(cleanup_run_id, entity_type))
                    is not None
                    and str(progress.status) == "completed"
                )
            )
            return CleanupOperationResult(
                cleanup_run_id=cleanup_run_id,
                archive_id=str(run.archive_id),
                status=cast(CleanupRunStatus, str(run.status)),
                deleted_record_count=int(run.deleted_record_count),
                protected_record_count=int(run.protected_record_count),
                missing_record_count=int(run.missing_record_count),
                skipped_record_count=int(run.skipped_record_count),
                completed_entity_phases=completed_phases,
                resumed=resumed,
            )

    def _assert_run_lease(self, run: RetentionCleanupRun, worker_id: str) -> None:
        now = utc_datetime(self._clock())
        if (
            str(run.status) != "running"
            or str(run.lease_owner) != worker_id
            or run.lease_expires_at is None
            or utc_datetime(cast(datetime, run.lease_expires_at)) <= now
        ):
            raise CleanupPersistenceError("cleanup_lease_lost")

    @staticmethod
    def _assert_snapshot(
        run: RetentionCleanupRun,
        expected: ArchiveStabilitySnapshot,
    ) -> None:
        if ArchiveStabilitySnapshot.from_dict(run.archive_snapshot) != expected:
            raise ArchiveIntegrityError("archive_snapshot_changed")

    @staticmethod
    def _add_audit(
        uow: UnitOfWork,
        *,
        event_type: str,
        cleanup_run_id: str,
        archive_id: str,
        timestamp: datetime,
        policy_version: str,
        archive_schema_version: str,
        status: str,
        deleted: int = 0,
        protected: int = 0,
        missing: int = 0,
        skipped: int = 0,
        error_code: str | None = None,
    ) -> None:
        assert uow.session is not None
        details: dict[str, Any] = {
            "cleanup_run_id": cleanup_run_id,
            "archive_id": archive_id,
            "policy_version": policy_version,
            "archive_schema_version": archive_schema_version,
            "status": status,
            "deleted_count": deleted,
            "protected_count": protected,
            "missing_count": missing,
            "skipped_count": skipped,
            "timestamp": utc_datetime(timestamp).isoformat(),
        }
        if error_code is not None:
            details["error_code"] = error_code
        uow.session.add(
            AuditEvent(
                audit_event_id=f"ae_{uuid.uuid4().hex}",
                timestamp=timestamp,
                event_type=event_type,
                entity_type="retention_cleanup",
                entity_id=cleanup_run_id,
                action=event_type,
                actor_type="system",
                actor_id="retention_cleanup_service",
                actor="system",
                details=details,
            )
        )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(exc, CleanupOperationError):
            return exc.code
        if isinstance(exc, CleanupPersistenceError):
            return exc.code
        if isinstance(exc, ArchiveIntegrityError):
            return "cleanup_archive_integrity_failed"
        if isinstance(exc, ArchiveStorageError):
            return "cleanup_archive_storage_failed"
        if isinstance(exc, IntegrityError):
            return "cleanup_database_failed"
        if isinstance(exc, (ValueError, TypeError)):
            return "cleanup_validation_failed"
        return "cleanup_operation_failed"
