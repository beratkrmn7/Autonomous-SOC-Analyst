from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from agent.config import get_settings

settings = get_settings()

from typing import Iterator
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from agent.config import Settings

Base = declarative_base()

def create_engine_factory(settings: Settings) -> Engine:
    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        
    # SQLite doesn't support pool_size and max_overflow in the same way, but SQLAlchemy handles it.
    kwargs = {
        "echo": settings.database_echo,
        "connect_args": connect_args,
    }
    
    if not settings.database_url.startswith("sqlite"):
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow
        kwargs["pool_timeout"] = settings.database_pool_timeout
        
    return create_engine(settings.database_url, **kwargs)

def create_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db(session_factory: sessionmaker) -> Iterator[Session]:
    db = session_factory()
    try:
        yield db
    finally:
        db.close()

