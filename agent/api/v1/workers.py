from fastapi import APIRouter, Depends, Query
from typing import Dict, Any
from contextlib import nullcontext
from agent.api.deps import get_uow, require_permission
from agent.application.authentication import AuthenticatedPrincipal
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import WorkerHeartbeat
from agent.config import get_settings
from agent.security.authorization import Permission
import datetime

router = APIRouter()

@router.get("", tags=["Workers"])
async def list_workers(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    uow: UnitOfWork = Depends(get_uow),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(Permission.WORKER_READ)
    ),
) -> Dict[str, Any]:
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)
    stale_threshold = now - datetime.timedelta(seconds=settings.worker_heartbeat_stale_seconds)

    uow_context = uow if uow.session is None else nullcontext(uow)
    with uow_context:
        assert uow.session is not None
        workers_query = uow.session.query(WorkerHeartbeat).order_by(
            WorkerHeartbeat.worker_id.asc()
        )
        total = workers_query.count()
        workers = workers_query.offset(skip).limit(limit).all()

        data = []
        for worker in workers:
            last_heartbeat = worker.last_heartbeat_at
            if last_heartbeat.tzinfo is None:
                last_heartbeat = last_heartbeat.replace(
                    tzinfo=datetime.timezone.utc
                )

            data.append({
                "worker_id": worker.worker_id,
                "worker_type": worker.worker_type,
                "status": worker.status,
                "last_heartbeat_at": (
                    worker.last_heartbeat_at.isoformat()
                    if worker.last_heartbeat_at
                    else None
                ),
                "current_job_id": worker.current_job_id,
                "stale": last_heartbeat < stale_threshold,
            })

        return {
            "items": data,
            "total": total,
            "skip": skip,
            "limit": limit,
        }
