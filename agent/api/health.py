from fastapi import APIRouter, Depends, Response
from typing import Dict
from sqlalchemy import text
from agent.api.deps import get_uow
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import WorkerHeartbeat
from agent.config import get_settings
import datetime

router = APIRouter()

@router.get("/live", tags=["Health"])
async def live():
    return {"status": "live"}

@router.get("/ready", tags=["Health"])
async def ready(response: Response, uow: UnitOfWork = Depends(get_uow)):
    settings = get_settings()
    components: Dict[str, str] = {
        "database": "up",
        "queue": "up",
        "worker": "up"
    }
    status = "ready"
    
    # 1. Check DB
    try:
        assert uow.session is not None
        uow.session.execute(text("SELECT 1"))
    except Exception:
        components["database"] = "down"
        status = "not_ready"
        
    # 2. Check Celery/Redis if enabled
    if settings.task_queue_backend == "celery":
        try:
            import redis
            r = redis.Redis.from_url(settings.celery_broker_url, socket_connect_timeout=2)
            r.ping()
            r.close()
        except Exception:
            components["queue"] = "down"
            status = "not_ready"
            
        # 3. Check for at least one non-stale worker
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            stale_threshold = now - datetime.timedelta(seconds=settings.worker_heartbeat_stale_seconds)
            assert uow.session is not None
            active_worker = uow.session.query(WorkerHeartbeat).filter(
                WorkerHeartbeat.last_heartbeat_at >= stale_threshold
            ).first()
            if not active_worker:
                components["worker"] = "down"
                status = "not_ready"
        except Exception:
            components["worker"] = "down"
            status = "not_ready"
            
    if status == "not_ready":
        response.status_code = 503
        
    return {
        "status": status,
        "components": components
    }
