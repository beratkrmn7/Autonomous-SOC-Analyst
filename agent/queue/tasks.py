import logging
from agent.queue.celery_app import celery_app
from agent.workers.analysis_worker import AnalysisWorker
from agent.config import get_settings

logger = logging.getLogger(__name__)

@celery_app.task(name="agent.queue.tasks.analyze_job_task")
def analyze_job_task(job_id: str) -> bool:
    """
    Celery task that processes a specific job_id using the AnalysisWorker.
    """
    logger.info(f"Celery task started for job {job_id}")
    settings = get_settings()
    worker = AnalysisWorker(staging_dir=settings.staging_dir, worker_id="celery_worker")
    return worker.process_job(job_id)
