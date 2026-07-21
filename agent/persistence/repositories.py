from datetime import datetime
from typing import Any, cast
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from agent.persistence.orm_models import (
    ApiCredential, Incident, DetectionSignal, CanonicalEvent,
    TriageRun, EvidenceItem, Report, AuditEvent,
    IngestionJob, IncidentCorrelationState
)
from agent.persistence.exceptions import RecordNotFoundError
from typing import List, Optional

class GenericRepository:
    def __init__(self, session: Session, model_cls):
        self.session = session
        self.model_cls = model_cls
        
    def add(self, entity):
        self.session.add(entity)
        return entity
        
    def get(self, id_val):
        # We assume standard primary key name or use session.get
        return self.session.get(self.model_cls, id_val)

    def get_for_update(self, id_val):
        """Load and lock an existing source row for projection-safe mutation."""
        return self.session.get(self.model_cls, id_val, with_for_update=True)
        
    def get_or_404(self, id_val):
        entity = self.get(id_val)
        if not entity:
            raise RecordNotFoundError(self.model_cls.__name__, str(id_val))
        return entity

    def list(self, skip: int = 0, limit: int = 100):
        return self.session.query(self.model_cls).offset(skip).limit(limit).all()

class IncidentRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, Incident)
        
    def get_by_status(self, status: str) -> List[Incident]:
        return self.session.query(Incident).filter(Incident.status == status).all()

class AuditEventRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, AuditEvent)
        
    def get_by_incident(self, incident_id: str) -> List[AuditEvent]:
        return self.session.query(AuditEvent).filter(AuditEvent.incident_id == incident_id).order_by(AuditEvent.timestamp.desc()).all()

class IngestionJobRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, IngestionJob)


class ApiCredentialRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, ApiCredential)

    def get_by_prefix(self, key_prefix: str) -> List[ApiCredential]:
        return (
            self.session.query(ApiCredential)
            .filter(ApiCredential.key_prefix == key_prefix)
            .all()
        )

    def list_for_administration(self) -> List[ApiCredential]:
        return (
            self.session.query(ApiCredential)
            .order_by(ApiCredential.created_at.asc(), ApiCredential.credential_id.asc())
            .all()
        )

class CanonicalEventRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, CanonicalEvent)

class DetectionSignalRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, DetectionSignal)

class TriageRunRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, TriageRun)

class EvidenceRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, EvidenceItem)

class ReportRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, Report)


class IncidentCorrelationStateRepository(GenericRepository):
    """Phase 6E.4A: persistent cross-job correlation state.

    `correlation_key` is the primary key, so concurrent first-writers race
    on a real unique-constraint violation (IntegrityError) rather than a
    read-then-write gap. Generation transitions use a guarded conditional
    UPDATE keyed on `version` (optimistic concurrency, same idiom as
    RetentionCleanupRepository._guarded_run_update) so a lost race is
    detected by rowcount rather than assumed to have succeeded.
    """

    def __init__(self, session: Session):
        super().__init__(session, IncidentCorrelationState)

    def get_by_key(self, correlation_key: str) -> Optional[IncidentCorrelationState]:
        return self.session.get(IncidentCorrelationState, correlation_key)

    def replace_expired_generation(
        self,
        correlation_key: str,
        *,
        expected_version: int,
        new_incident_id: str,
        new_generation: int,
        profile: dict,
        first_seen: datetime,
        last_seen: datetime,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        """Guarded transition from an expired generation to a new one.

        Returns False (never raises) when another worker already won the
        transition, so the caller can re-read and follow the winner.
        """
        result = cast(CursorResult[Any], self.session.execute(
            update(IncidentCorrelationState)
            .where(
                IncidentCorrelationState.correlation_key == correlation_key,
                IncidentCorrelationState.version == expected_version,
            )
            .values(
                incident_id=new_incident_id,
                generation=new_generation,
                profile=profile,
                first_seen=first_seen,
                last_seen=last_seen,
                expires_at=expires_at,
                version=IncidentCorrelationState.version + 1,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        ))
        return result.rowcount == 1

    def extend_active_generation(
        self,
        correlation_key: str,
        *,
        expected_version: int,
        profile: dict,
        first_seen: datetime,
        last_seen: datetime,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        """Guarded refresh of an active generation's window/profile/TTL.

        Never changes incident_id or generation. Returns False (never
        raises) when another worker already updated this row first.
        """
        result = cast(CursorResult[Any], self.session.execute(
            update(IncidentCorrelationState)
            .where(
                IncidentCorrelationState.correlation_key == correlation_key,
                IncidentCorrelationState.version == expected_version,
            )
            .values(
                profile=profile,
                first_seen=first_seen,
                last_seen=last_seen,
                expires_at=expires_at,
                version=IncidentCorrelationState.version + 1,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        ))
        return result.rowcount == 1

    def delete_expired_before(self, cutoff: datetime, limit: int) -> int:
        """Bounded cleanup: delete up to `limit` rows expired before cutoff."""
        keys = list(
            self.session.scalars(
                select(IncidentCorrelationState.correlation_key)
                .where(IncidentCorrelationState.expires_at < cutoff)
                .order_by(IncidentCorrelationState.expires_at.asc())
                .limit(limit)
            )
        )
        if not keys:
            return 0
        result = cast(CursorResult[Any], self.session.execute(
            IncidentCorrelationState.__table__.delete().where(
                IncidentCorrelationState.correlation_key.in_(keys)
            )
        ))
        return result.rowcount or 0
