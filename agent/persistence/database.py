from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from agent.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url, 
    echo=settings.database_echo,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
