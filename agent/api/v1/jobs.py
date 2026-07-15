import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from agent.api.deps import (
    get_dispatcher,
    get_staging_store,
    get_uow,
    require_permission,
)
from agent.application.authentication import AuthenticatedPrincipal
from agent.application.background_service import BackgroundAnalysisService
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.staging import FileStagingStore
from agent.persistence.orm_models import IngestionJob
from agent.queue.dispatchers import AnalysisJobDispatcher
from agent.errors import QueuePublishFailedError
from agent.application.cancellation import (
    JobCancellationService,
    JobNotCancellableError,
    JobNotFoundError,
)
from agent.security.authorization import Permission

router = APIRouter(tags=["jobs"])


def _iso_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return value.isoformat()

@router.post("/analysis-jobs/file", status_code=202)
async def submit_file_job(
    file: UploadFile = File(...),
    uow: UnitOfWork = Depends(get_uow),
    staging_store: FileStagingStore = Depends(get_staging_store),
    dispatcher: AnalysisJobDispatcher = Depends(get_dispatcher),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(Permission.JOB_SUBMIT)
    ),
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


@router.post("/analysis-jobs/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    request: Request,
    uow: UnitOfWork = Depends(get_uow),
    staging_store: FileStagingStore = Depends(get_staging_store),
    principal: AuthenticatedPrincipal = Depends(
        require_permission(Permission.JOB_CANCEL)
    ),
):
    service = JobCancellationService(uow=uow, staging_store=staging_store)
    try:
        result = service.cancel(
            job_id,
            actor_type=principal.subject_type,
            actor_id=principal.subject_id,
            request_id=request.state.request_id,
        )
    except JobNotFoundError:
        return JSONResponse(status_code=404, content={"code": "job_not_found"})
    except JobNotCancellableError as exc:
        return JSONResponse(
            status_code=409,
            content={"code": "job_not_cancellable", "status": exc.status},
        )

    content = {
        "job_id": result.job_id,
        "status": result.status,
        "cancel_requested_at": _iso_utc(result.cancel_requested_at),
    }
    if result.cancelled_at is not None:
        content["cancelled_at"] = _iso_utc(result.cancelled_at)

    return JSONResponse(
        status_code=202 if result.status == "cancel_requested" else 200,
        content=content,
    )

@router.get("/analysis-jobs/{job_id}")
async def get_job_status(
    job_id: str,
    uow: UnitOfWork = Depends(get_uow),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(Permission.JOB_READ)
    ),
):
    with uow:
        assert uow.session is not None
        job = uow.session.query(IngestionJob).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        return {
            "job_id": job.id,
            "status": job.status,
            "queued_at": _iso_utc(job.queued_at),
            "started_at": _iso_utc(job.started_at),
            "completed_at": _iso_utc(job.completed_at),
            "error_code": job.error_code,
            "cancel_requested_at": _iso_utc(job.cancel_requested_at),
            "cancelled_at": _iso_utc(job.cancelled_at),
            "cancel_reason_code": job.cancel_reason_code,
        }

@router.get("/analysis-jobs/{job_id}/result")
async def get_job_result(
    job_id: str,
    uow: UnitOfWork = Depends(get_uow),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(Permission.JOB_READ)
    ),
):
    with uow:
        assert uow.session is not None
        job = uow.session.query(IngestionJob).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
            
        if job.status in ("queued", "processing", "cancel_requested"):
            return JSONResponse(status_code=202, content={"status": job.status, "message": "Job is still processing"})

        if job.status == "cancelled":
            return {"status": "cancelled"}
            
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
