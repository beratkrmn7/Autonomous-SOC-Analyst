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

    def process_job(self, job_id: str) -> str:
        """Processes a specific job by ID. Returns the resulting status ('completed', 'failed', 'retry', or 'ignored')."""
        db = self.session_factory()
        try:
            from agent.config import get_settings
            from agent.errors import RetryableJobError, PermanentJobError
            import datetime
            settings = get_settings()
            
            now = datetime.datetime.now(datetime.timezone.utc)
            lease_expires = now + datetime.timedelta(seconds=settings.job_processing_lease_seconds)
            
            # Atomic check-and-set
            updated = db.query(IngestionJob).filter(
                IngestionJob.id == job_id,
                IngestionJob.status == "queued"
            ).update({
                "status": "processing",
                "worker_id": self.worker_id,
                "started_at": now,
                "last_attempt_at": now,
                "lease_expires_at": lease_expires,
                "attempt_count": IngestionJob.attempt_count + 1
            })
            db.commit()
            
            if not updated:
                return "ignored" # Someone else grabbed it or it's not queued
                
            logger.info(f"Worker {self.worker_id} claimed job {job_id}")
            
            job = db.query(IngestionJob).get(job_id)
            if not job:
                return "ignored"

            # 2. Process the job
            file_path = None
            job_status = "completed"
            
            try:
                try:
                    file_path = self.staging_store.get_file_path(job_id)
                except Exception as e:
                    # If staging file is missing, it's a permanent error
                    raise PermanentJobError("staging_file_missing") from e
                
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
                
                # Successful execution
                db.refresh(job)
                job.status = "completed"
                job.lease_expires_at = None
                job.next_retry_at = None
                db.commit()
                
                # Clean up staging only on completion or permanent failure
                self.staging_store.remove_file(job_id)
                logger.info(f"Worker {self.worker_id} cleaned up staging for job {job_id}")
                return "completed"

            except Exception as e:
                db.rollback()
                failed_job = db.query(IngestionJob).get(job_id)
                if not failed_job:
                    return "failed"
                
                # Determine if retryable
                is_retryable = isinstance(e, RetryableJobError)
                
                if is_retryable and failed_job.attempt_count < settings.job_max_attempts:
                    # Schedule retry
                    delay_seconds = min(
                        settings.job_retry_base_seconds * (2 ** (failed_job.attempt_count - 1)),
                        settings.job_retry_max_seconds
                    )
                    now = datetime.datetime.now(datetime.timezone.utc)
                    failed_job.status = "queued"
                    failed_job.error_code = type(e).__name__
                    failed_job.worker_id = None
                    failed_job.lease_expires_at = None
                    failed_job.next_retry_at = now + datetime.timedelta(seconds=delay_seconds)
                    db.commit()
                    logger.warning(f"Worker {self.worker_id} temporarily failed job {job_id}, retrying in {delay_seconds}s. Reason: {type(e).__name__}")
                    job_status = "retry"
                else:
                    # Permanent failure or max attempts reached
                    failed_job.status = "failed"
                    failed_job.worker_id = None
                    failed_job.lease_expires_at = None
                    
                    if isinstance(e, PermanentJobError):
                        failed_job.error_code = str(e)
                    elif is_retryable:
                        failed_job.error_code = "max_attempts_reached"
                    else:
                        failed_job.error_code = "worker_execution_failed"
                        
                    db.commit()
                    logger.error(f"Worker {self.worker_id} permanently failed job {job_id}. Reason: {failed_job.error_code}")
                    
                    # Clean up staging on terminal failure
                    self.staging_store.remove_file(job_id)
                    logger.info(f"Worker {self.worker_id} cleaned up staging for job {job_id} after terminal failure")
                    job_status = "failed"
                    
            return job_status

        finally:
            db.close()

    def run_once(self) -> bool:
        """Runs one job. Returns True if a job was processed, False if queue was empty."""
        db = self.session_factory()
        try:
            # 1. Find a job
            job = db.query(IngestionJob).filter(
                IngestionJob.status == "queued",
                (IngestionJob.next_retry_at.is_(None)) | (IngestionJob.next_retry_at <= func.now())
            ).order_by(IngestionJob.queued_at.asc()).first()
            
            if not job:
                return False
                
            job_id = job.id
            
        finally:
            db.close()

        status = self.process_job(job_id)
        return status in ("completed", "failed", "retry")

    def recover_stale_jobs(self) -> int:
        """Finds jobs that have been processing longer than their lease and requeues or fails them. Returns count."""
        db = self.session_factory()
        try:
            from agent.config import get_settings
            import datetime
            settings = get_settings()
            
            # Find stale processing jobs
            stale_jobs = db.query(IngestionJob).filter(
                IngestionJob.status == "processing",
                IngestionJob.lease_expires_at.is_not(None),
                IngestionJob.lease_expires_at <= func.now()
            ).all()
            
            count = 0
            for job in stale_jobs:
                logger.warning(f"Worker {self.worker_id} recovering stale job {job.id}")
                
                if job.attempt_count < settings.job_max_attempts:
                    # Requeue
                    delay_seconds = min(
                        settings.job_retry_base_seconds * (2 ** (job.attempt_count - 1)),
                        settings.job_retry_max_seconds
                    )
                    now = datetime.datetime.now(datetime.timezone.utc)
                    job.status = "queued"
                    job.worker_id = None
                    job.lease_expires_at = None
                    job.next_retry_at = now + datetime.timedelta(seconds=delay_seconds)
                else:
                    # Fail permanently
                    job.status = "failed"
                    job.error_code = "processing_lease_expired"
                    job.worker_id = None
                    job.lease_expires_at = None
                    # Clean up staging
                    try:
                        self.staging_store.remove_file(job.id)
                    except Exception as e:
                        logger.error(f"Failed to clean up staging for stale job {job.id}: {e}")
                count += 1
            
            if count > 0:
                db.commit()
                
            return count
        finally:
            db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run one job and exit")
    parser.add_argument("--recover-stale", action="store_true", help="Run stale job recovery and exit")
    parser.add_argument("--staging-dir", type=str, default="/tmp/agent_staging", help="Path to staging directory")
    args = parser.parse_args()

    worker = AnalysisWorker(staging_dir=args.staging_dir)
    
    if args.recover_stale:
        logger.info("Running stale job recovery")
        count = worker.recover_stale_jobs()
        logger.info(f"Recovered {count} stale jobs.")
        sys.exit(0)
    
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
