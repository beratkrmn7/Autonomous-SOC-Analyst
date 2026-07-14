import logging
from typing import Protocol
from agent.queue.celery_app import celery_app

logger = logging.getLogger(__name__)

class AnalysisJobDispatcher(Protocol):
    def enqueue(self, job_id: str) -> None:
        """Enqueues an analysis job for processing."""
        ...

class DatabasePollingDispatcher:
    def enqueue(self, job_id: str) -> None:
        """
        No-op implementation. 
        The existing database worker polls the database for queued jobs.
        """
        logger.info(f"Database dispatcher: job {job_id} remains queued for polling workers.")

class CeleryAnalysisJobDispatcher:
    def enqueue(self, job_id: str) -> None:
        """
        Publishes the job_id to the Celery broker.
        """
        logger.info(f"Celery dispatcher: publishing job {job_id} to broker.")
        celery_app.send_task(
            "agent.queue.tasks.analyze_job_task",
            args=[job_id],
            task_id=job_id,
        )
