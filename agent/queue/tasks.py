import logging
from agent.queue.celery_app import celery_app
from agent.workers.analysis_worker import AnalysisWorker
from agent.config import get_settings

logger = logging.getLogger(__name__)

@celery_app.task(name="agent.queue.tasks.analyze_job_task", bind=True, max_retries=None)
def analyze_job_task(self, job_id: str) -> str:
    """
    Celery task that processes a specific job_id using the AnalysisWorker.
    """
    logger.info(f"Celery task started for job {job_id}")
    settings = get_settings()
    worker = AnalysisWorker(staging_dir=settings.staging_dir, worker_id="celery_worker")
    status = worker.process_job(job_id)
    
    if status == "retry":
        # The database state is already committed as "queued" with next_retry_at.
        # But we also tell Celery to retry this task so it stays in the queue.
        # We can read the DB's next_retry_at or just use a generic backoff here
        # Actually, let's look up the job's next_retry_at to compute countdown.
        db = worker.session_factory()
        try:
            from agent.persistence.orm_models import IngestionJob
            import datetime
            job = db.query(IngestionJob).get(job_id)
            if job and job.next_retry_at:
                now = datetime.datetime.now(datetime.timezone.utc)
                if job.next_retry_at.tzinfo is None:
                    # ensure tz-aware
                    next_retry_at = job.next_retry_at.replace(tzinfo=datetime.timezone.utc)
                else:
                    next_retry_at = job.next_retry_at
                countdown = max(0, int((next_retry_at - now).total_seconds()))
                self.retry(countdown=countdown)
        finally:
            db.close()
            
    return status
