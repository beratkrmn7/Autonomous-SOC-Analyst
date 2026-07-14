import logging
from celery import Celery
from agent.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

celery_app = Celery("soc_analysis")

# Configure Celery
celery_app.conf.update(
    broker_url=settings.celery_broker_url,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_ignore_result=True,  # The SOC database is already the result store
    task_default_queue=settings.celery_queue_name,
)

# Discover tasks
celery_app.autodiscover_tasks(["agent.queue"])
