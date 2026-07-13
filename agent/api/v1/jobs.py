from fastapi import APIRouter, Depends, UploadFile, File, Header, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional

from agent.api.deps import get_uow, get_staging_store
from agent.application.background_service import BackgroundAnalysisService
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.staging import FileStagingStore
from agent.persistence.orm_models import IngestionJob

router = APIRouter(tags=["jobs"])

@router.post("/analysis-jobs/file", status_code=202)
async def submit_file_job(
    file: UploadFile = File(...),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    pipeline_version: Optional[str] = Header(None, alias="X-Pipeline-Version"),
    analysis_mode: Optional[str] = Header(None, alias="X-Analysis-Mode"),
    uow: UnitOfWork = Depends(get_uow),
    staging_store: FileStagingStore = Depends(get_staging_store)
):
    service = BackgroundAnalysisService(uow=uow, staging_store=staging_store)
    
    # We read from file.file which is a SpooledTemporaryFile (binary stream)
    job_id, reused = service.submit_file(
        stream=file.file,
        original_filename=file.filename or "upload.bin",
        source_name="api",
        idempotency_key=idempotency_key,
        pipeline_version=pipeline_version,
        analysis_mode=analysis_mode
    )
    
    return JSONResponse(
        status_code=202,
        content={
            "job_id": job_id,
            "status": "queued",
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
