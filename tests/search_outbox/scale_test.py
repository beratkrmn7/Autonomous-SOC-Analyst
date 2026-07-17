import time
from datetime import datetime, timezone

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from agent.persistence.database import Base
from agent.persistence.unit_of_work import UnitOfWork
from agent.opensearch.documents import CanonicalEventSearchDocument
from agent.config import get_settings

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def run_scale_test():
    settings = get_settings()
    # Mock settings
    settings.opensearch_enabled = True
    settings.opensearch_schema_version = "v1"
    
    uow = UnitOfWork(session_factory=SessionLocal)
    
    print("Starting scale test for 10,000 outbox records...")
    start_time = time.time()
    
    with uow:
        for i in range(10000):
            doc = CanonicalEventSearchDocument(
                schema_version="v1",
                entity_id=f"event_{i}",
                document_version=1,
                indexed_at=datetime.now(timezone.utc),
                source_updated_at=datetime.now(timezone.utc),
                event_id=f"event_{i}",
                timestamp=datetime.now(timezone.utc),
                safe_message_excerpt="test scale"
            )
            uow.search_index_outbox.enqueue_upsert(doc)
            
            if i % 1000 == 0 and i > 0:
                print(f"Enqueued {i} records...")
        
        # Commit transaction
        uow.commit()
        
    duration = time.time() - start_time
    print(f"Successfully enqueued 10,000 records in {duration:.2f} seconds.")

if __name__ == "__main__":
    run_scale_test()
