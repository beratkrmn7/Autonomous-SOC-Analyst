from typing import Optional
from sqlalchemy.orm import Session
from agent.persistence.database import SessionLocal

class UnitOfWork:
    def __init__(self, session_factory=SessionLocal):
        self.session_factory = session_factory
        self.session: Optional[Session] = None
        
    def __enter__(self):
        self.session = self.session_factory()
        return self
        
    def __exit__(self, exc_type, exc_val, traceback):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        self.session.close()
        
    def commit(self):
        if self.session:
            self.session.commit()
            
    def rollback(self):
        if self.session:
            self.session.rollback()
