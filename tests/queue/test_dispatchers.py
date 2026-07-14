from unittest.mock import patch
from agent.queue.dispatchers import DatabasePollingDispatcher, CeleryAnalysisJobDispatcher

def test_database_dispatcher_no_op():
    dispatcher = DatabasePollingDispatcher()
    # Should run without error and do nothing
    dispatcher.enqueue("test-job-id")

@patch("agent.queue.dispatchers.celery_app.send_task")
def test_celery_dispatcher_publishes_job_id(mock_send_task):
    dispatcher = CeleryAnalysisJobDispatcher()
    job_id = "test-job-id-123"
    
    dispatcher.enqueue(job_id)
    
    mock_send_task.assert_called_once_with(
        "agent.queue.tasks.analyze_job_task",
        args=[job_id],
        task_id=job_id,
    )
