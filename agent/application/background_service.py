import uuid
from typing import BinaryIO, Tuple
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import IngestionJob
from agent.application.staging import FileStagingStore

class BackgroundAnalysisService:
    def __init__(self, uow: UnitOfWork, staging_store: FileStagingStore):
        self.uow = uow
        self.staging_store = staging_store

    def submit_file(
        self,
        stream: BinaryIO,
        original_filename: str,
        source_name: str,
        pipeline_version: str,
        analysis_mode: str = "analyze",
    ) -> Tuple[str, bool, str]:
        """
        Submits a file for background analysis.
        Returns a tuple of (job_id, reused, status).
        """
        import hashlib
        job_id = str(uuid.uuid4())
        reused = False

        with self.uow:
            assert self.uow.session is not None
            
            # 1. Stage the file (which gives us the SHA-256)
            staged_path, file_sha256 = self.staging_store.stage_file(stream, job_id, original_filename)

            # 2. Derive idempotency key
            idemp_string = f"{file_sha256}:{pipeline_version}:{analysis_mode}"
            idempotency_key = hashlib.sha256(idemp_string.encode('utf-8')).hexdigest()

            # 3. Check idempotency
            job = self.uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
            if job:
                if job.status in ("queued", "processing", "completed"):
                    self.staging_store.remove_file(job_id) # Clean up the newly staged file because we reuse the old job
                    if job.status == "completed":
                        job.reused_count += 1  # type: ignore
                        job.last_requested_at = func.now()  # type: ignore
                        self.uow.session.commit()
                    return str(job.id), True, str(job.status)
                elif job.status == "failed":
                    # Move the newly uploaded file to the existing job's staging path
                    self.staging_store.move_file(job_id, str(job.id))
                    
                    # Retry
                    job.status = "queued"  # type: ignore
                    job.error_code = None  # type: ignore
                    job.queued_at = func.now()  # type: ignore
                    job.reused_count += 1  # type: ignore
                    job.last_requested_at = func.now()  # type: ignore
                    self.uow.session.commit()
                    return str(job.id), True, "queued"

            # 4. Create a new IngestionJob
            job = IngestionJob(
                id=job_id,
                idempotency_key=idempotency_key,
                source_name=source_name,
                original_filename=original_filename,
                file_sha256=file_sha256,
                pipeline_version=pipeline_version,
                analysis_mode=analysis_mode,
                status="queued",
                queued_at=func.now()
            )
            self.uow.ingestion_jobs.add(job)
            
            try:
                self.uow.session.commit()
            except IntegrityError:
                self.uow.session.rollback()
                # If there's an integrity error, it might be due to a concurrent request with the same idempotency key
                existing_job = self.uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
                if existing_job:
                    self.staging_store.remove_file(job_id) # Clean up the newly staged file
                    return str(existing_job.id), True, str(existing_job.status)
                raise # Re-raise if it's not handled

        return job_id, reused, "queued"
