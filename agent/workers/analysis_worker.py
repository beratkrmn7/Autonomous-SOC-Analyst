import argparse
import sys
import time
import socket
import logging
from sqlalchemy.sql import func
from agent.api.deps import session_factory as default_session_factory
from agent.persistence.orm_models import IngestionJob
from agent.application.analysis_service import AnalysisService
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.staging import LocalFileStagingStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("worker")

class AnalysisWorker:
    def __init__(self, staging_dir: str = "/tmp/agent_staging", worker_id: str = socket.gethostname(), session_factory=None):
        self.worker_id = worker_id
        self.staging_store = LocalFileStagingStore(staging_dir=staging_dir)
        self.session_factory = session_factory or default_session_factory

    def process_job(self, job_id: str) -> bool:
        """Processes a specific job by ID. Returns True if successfully claimed and processed, False otherwise."""
        db = self.session_factory()
        try:
            # Atomic check-and-set
            updated = db.query(IngestionJob).filter(
                IngestionJob.id == job_id,
                IngestionJob.status == "queued"
            ).update({
                "status": "processing",
                "worker_id": self.worker_id,
                "started_at": func.now(),
                "attempt_count": IngestionJob.attempt_count + 1
            })
            db.commit()
            
            if not updated:
                return False # Someone else grabbed it or it's not queued
                
            logger.info(f"Worker {self.worker_id} claimed job {job_id}")
            
            job = db.query(IngestionJob).get(job_id)
            if not job:
                return False

            # 2. Process the job
            file_path = None
            try:
                file_path = self.staging_store.get_file_path(job_id)
                
                # Use a fresh UnitOfWork for the service
                uow = UnitOfWork(session_factory=self.session_factory)
                service = AnalysisService(uow=uow)
                
                logger.info(f"Worker {self.worker_id} starting analysis for job {job_id}")
                
                service.analyze_file(
                    file_path=file_path,
                    run_triage=True, # Background job runs full triage
                    source_name=job.source_name,
                    file_sha256=job.file_sha256,
                    idempotency_key=job.idempotency_key,
                    pipeline_version=job.pipeline_version,
                    analysis_mode=job.analysis_mode,
                    job_id=job.id
                )
            except Exception as e:
                logger.error(f"Worker {self.worker_id} failed job {job_id}: {e}")
                
                # Mark as failed
                db.rollback()
                failed_job = db.query(IngestionJob).get(job_id)
                if failed_job:
                    failed_job.status = "failed"
                    failed_job.error_code = "WORKER_EXECUTION_FAILED"
                    db.commit()
            finally:
                # 3. Clean up staging
                self.staging_store.remove_file(job_id)
                logger.info(f"Worker {self.worker_id} cleaned up staging for job {job_id}")

            return True

        finally:
            db.close()

    def run_once(self) -> bool:
        """Runs one job. Returns True if a job was processed, False if queue was empty."""
        db = self.session_factory()
        try:
            # 1. Find a job
            job = db.query(IngestionJob).filter(IngestionJob.status == "queued").order_by(IngestionJob.queued_at.asc()).first()
            
            if not job:
                return False
                
            job_id = job.id
            
        finally:
            db.close()

        return self.process_job(job_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run one job and exit")
    parser.add_argument("--staging-dir", type=str, default="/tmp/agent_staging", help="Path to staging directory")
    args = parser.parse_args()

    worker = AnalysisWorker(staging_dir=args.staging_dir)
    
    if args.once:
        logger.info("Running in --once mode")
        processed = worker.run_once()
        if processed:
            logger.info("Job processed successfully.")
        else:
            logger.info("No jobs to process.")
        sys.exit(0)
    else:
        logger.info("Starting polling worker...")
        while True:
            processed = worker.run_once()
            if not processed:
                time.sleep(2)
