import datetime

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text

from agent.api.deps import get_optional_oidc_authentication_service, get_uow
from agent.application.oidc_authentication import OidcJwtAuthenticationService
from agent.config import get_settings
from agent.persistence.orm_models import WorkerHeartbeat
from agent.persistence.unit_of_work import UnitOfWork

router = APIRouter()


@router.get("/live", tags=["Health"])
async def live():
    return {"status": "live"}


@router.get("/ready", tags=["Health"])
async def ready(
    response: Response,
    uow: UnitOfWork = Depends(get_uow),
    oidc_service: OidcJwtAuthenticationService | None = Depends(
        get_optional_oidc_authentication_service
    ),
):
    settings = get_settings()
    components: dict[str, str] = {
        "database": "up",
        "queue": "up",
        "worker": "up",
    }
    status = "ready"

    session = uow.session
    close_session = False

    # 1. Check DB
    try:
        if session is None:
            session = uow.session_factory()
            close_session = True
        session.execute(text("SELECT 1"))
    except Exception:
        components["database"] = "down"
        status = "not_ready"

    if settings.auth_mode in ("oidc", "hybrid"):
        components["identity_provider"] = "up"
        try:
            if oidc_service is None:
                raise RuntimeError("oidc_service_unavailable")
            oidc_service.check_provider()
        except Exception:
            components["identity_provider"] = "down"
            status = "not_ready"

    # 2. Check Celery/Redis if enabled
    if settings.task_queue_backend == "celery":
        redis_client = None
        try:
            import redis

            redis_client = redis.Redis.from_url(
                settings.celery_broker_url,
                socket_connect_timeout=2,
            )
            redis_client.ping()
        except Exception:
            components["queue"] = "down"
            status = "not_ready"
        finally:
            if redis_client is not None:
                try:
                    redis_client.close()
                except Exception:
                    components["queue"] = "down"
                    status = "not_ready"

        # 3. Check for at least one non-stale worker
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            stale_threshold = now - datetime.timedelta(
                seconds=settings.worker_heartbeat_stale_seconds
            )
            if session is None:
                raise RuntimeError("database_session_unavailable")
            active_worker = session.query(WorkerHeartbeat).filter(
                WorkerHeartbeat.last_heartbeat_at >= stale_threshold
            ).first()
            if not active_worker:
                components["worker"] = "down"
                status = "not_ready"
        except Exception:
            components["worker"] = "down"
            status = "not_ready"

    if close_session and session is not None:
        try:
            session.close()
        except Exception:
            components["database"] = "down"
            status = "not_ready"

    if status == "not_ready":
        response.status_code = 503

    return {"status": status, "components": components}
