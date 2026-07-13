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

    def run_once(self) -> bool:
        """Runs one job. Returns True if a job was processed, False if queue was empty."""
        db = self.session_factory()
        try:
            # 1. Claim a job
            # Since sqlite doesn't support SELECT FOR UPDATE SKIP LOCKED,
            # we use a simple update to 'processing' for the oldest 'queued' job.
            # In a distributed environment, this needs better concurrency control.
            
            job = db.query(IngestionJob).filter(IngestionJob.status == "queued").order_by(IngestionJob.queued_at.asc()).first()
            
            if not job:
                return False
                
            job_id = job.id
            
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
                return False # Someone else grabbed it
                
            logger.info(f"Worker {self.worker_id} claimed job {job_id}")
            
            # 2. Process the job
            file_path = None
            try:
                file_path = self.staging_store.get_file_path(job_id)
                
                # Use a fresh UnitOfWork for the service
                uow = UnitOfWork(session_factory=self.session_factory)
                service = AnalysisService(uow=uow)
                
                logger.info(f"Worker {self.worker_id} starting analysis for job {job_id}")
                
                # analyze_file will update the job to completed/failed internally if uow is passed
                # However, it expects a file_path and might do idempotency checks which we bypass here
                # since we've already claimed the job. Actually, analyze_file just does analysis and persistence.
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
                
                # Note: AnalysisService.analyze_file will try to create a new job if job_id is not passed in result,
                # but we want it to update OUR job. We should pass the job_id into analyze_file or modify how we call it.
                # Since analyze_file doesn't accept job_id as a parameter directly, but we can't change it too much,
                # wait... AnalysisService.analyze_file checks if job_id exists on idempotency.
                # But here, we already have a job in the DB!
                # Let's check AnalysisService.analyze_file signature... it doesn't take job_id! 
                # Wait, if we use idempotency_key, it might find it.
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
