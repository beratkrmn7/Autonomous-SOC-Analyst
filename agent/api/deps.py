from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.config import get_settings

# Global engine/session factory for FastAPI
settings = get_settings()
engine = create_engine_factory(settings)
session_factory = create_session_factory(engine)

def get_uow() -> UnitOfWork:
    return UnitOfWork(session_factory)
