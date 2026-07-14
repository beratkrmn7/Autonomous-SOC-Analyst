from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from agent.api.deps import get_uow, get_staging_store, get_dispatcher
from agent.application.background_service import BackgroundAnalysisService
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.staging import FileStagingStore
from agent.persistence.orm_models import IngestionJob
from agent.queue.dispatchers import AnalysisJobDispatcher
from agent.errors import QueuePublishFailedError

router = APIRouter(tags=["jobs"])

@router.post("/analysis-jobs/file", status_code=202)
async def submit_file_job(
    file: UploadFile = File(...),
    uow: UnitOfWork = Depends(get_uow),
    staging_store: FileStagingStore = Depends(get_staging_store),
    dispatcher: AnalysisJobDispatcher = Depends(get_dispatcher)
):
    from agent.config import get_settings
    settings = get_settings()
    
    service = BackgroundAnalysisService(uow=uow, staging_store=staging_store, dispatcher=dispatcher)
    
    try:
        # We read from file.file which is a SpooledTemporaryFile (binary stream)
        job_id, reused, status = service.submit_file(
            stream=file.file,
            original_filename=file.filename or "upload.bin",
            source_name="api",
            pipeline_version=settings.pipeline_version,
            analysis_mode="analyze"
        )
    except QueuePublishFailedError as e:
        return JSONResponse(
            status_code=503,
            content={
                "job_id": e.job_id,
                "error_code": e.error_code
            }
        )
    
    return JSONResponse(
        status_code=202,
        content={
            "job_id": job_id,
            "status": status,
            "reused": reused
        }
    )

@router.get("/analysis-jobs/{job_id}")
async def get_job_status(job_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        assert uow.session is not None
        job = uow.session.query(IngestionJob).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        return {
            "job_id": job.id,
            "status": job.status,
            "queued_at": job.queued_at.isoformat() if job.queued_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "error_code": job.error_code
        }

@router.get("/analysis-jobs/{job_id}/result")
async def get_job_result(job_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        assert uow.session is not None
        job = uow.session.query(IngestionJob).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        if job.status in ("queued", "processing"):
            return JSONResponse(status_code=202, content={"status": job.status, "message": "Job is still processing"})
            
        if job.status == "failed":
            return {
                "status": "failed",
                "error_code": job.error_code or "UNKNOWN_ERROR"
            }
            
        # Completed job results
        incident_ids = [inc.incident_id for inc in job.incidents]
        
        # Gather reports associated with this job
        reports = []
        for report in job.reports:
            reports.append({
                "incident_id": report.incident_id,
                "report_id": report.report_id
            })
            
        return {
            "status": "completed",
            "incident_ids": incident_ids,
            "reports": reports
        }
