import logging
import datetime
import hashlib
import platform
from typing import Optional
from agent.api.deps import session_factory as default_session_factory
from agent.persistence.orm_models import WorkerHeartbeat

logger = logging.getLogger(__name__)

class WorkerHeartbeatService:
    def __init__(self, session_factory=None):
        self.session_factory = session_factory or default_session_factory

    def _get_hostname_hash(self) -> str:
        hostname = platform.node() or "unknown"
        return hashlib.sha256(hostname.encode()).hexdigest()[:16]

    def register_startup(self, worker_id: str, worker_type: str, version: str = "1.0.0"):
        """Register a worker on startup or update its initial heartbeat."""
        db = self.session_factory()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            hostname_hash = self._get_hostname_hash()
            
            heartbeat = db.query(WorkerHeartbeat).get(worker_id)
            if not heartbeat:
                heartbeat = WorkerHeartbeat(
                    worker_id=worker_id,
                    worker_type=worker_type,
                    status="starting",
                    started_at=now,
                    last_heartbeat_at=now,
                    hostname_hash=hostname_hash,
                    version=version
                )
                db.add(heartbeat)
            else:
                heartbeat.worker_type = worker_type
                heartbeat.status = "starting"
                heartbeat.started_at = now
                heartbeat.last_heartbeat_at = now
                heartbeat.hostname_hash = hostname_hash
                heartbeat.version = version
                
            db.commit()
            logger.info(f"Worker {worker_id} registered heartbeat at startup")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to register worker heartbeat for {worker_id}: {type(e).__name__}")
        finally:
            db.close()

    def update_heartbeat(self, worker_id: str, status: str, current_job_id: Optional[str] = None):
        """Update the heartbeat timestamp and status for a worker."""
        db = self.session_factory()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            heartbeat = db.query(WorkerHeartbeat).get(worker_id)
            if heartbeat:
                heartbeat.status = status
                heartbeat.last_heartbeat_at = now
                heartbeat.current_job_id = current_job_id
                db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update worker heartbeat for {worker_id}: {type(e).__name__}")
        finally:
            db.close()
