from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.config import get_settings

# Global engine/session factory for FastAPI
settings = get_settings()
engine = create_engine_factory(settings)
session_factory = create_session_factory(engine)

def get_uow() -> UnitOfWork:
    return UnitOfWork(session_factory)

def get_staging_store():
    from agent.application.staging import LocalFileStagingStore
    return LocalFileStagingStore(staging_dir=settings.staging_dir)

def get_dispatcher():
    from agent.queue.dispatchers import DatabasePollingDispatcher, CeleryAnalysisJobDispatcher
    if settings.task_queue_backend == "celery":
        return CeleryAnalysisJobDispatcher()
    return DatabasePollingDispatcher()
