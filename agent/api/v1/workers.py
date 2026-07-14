from fastapi import APIRouter, Depends, Query
from typing import Dict, Any
from agent.api.deps import get_uow
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import WorkerHeartbeat
from agent.config import get_settings
import datetime

router = APIRouter()

@router.get("", tags=["Workers"])
async def list_workers(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    uow: UnitOfWork = Depends(get_uow)
) -> Dict[str, Any]:
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)
    stale_threshold = now - datetime.timedelta(seconds=settings.worker_heartbeat_stale_seconds)
    
    assert uow.session is not None
    workers_query = uow.session.query(WorkerHeartbeat).order_by(WorkerHeartbeat.worker_id.asc())
    total = workers_query.count()
    workers = workers_query.offset(skip).limit(limit).all()
    
    data = []
    for w in workers:
        # Determine stale
        # Make sure both are timezone-aware or both timezone-naive before comparing
        w_last_heartbeat = w.last_heartbeat_at
        if w_last_heartbeat.tzinfo is None:
            w_last_heartbeat = w_last_heartbeat.replace(tzinfo=datetime.timezone.utc)
            
        stale = w_last_heartbeat < stale_threshold
        
        data.append({
            "worker_id": w.worker_id,
            "worker_type": w.worker_type,
            "status": w.status,
            "last_heartbeat_at": w.last_heartbeat_at.isoformat() if w.last_heartbeat_at else None,
            "current_job_id": w.current_job_id,
            "stale": stale
        })
        
    return {
        "items": data,
        "total": total,
        "skip": skip,
        "limit": limit
    }
