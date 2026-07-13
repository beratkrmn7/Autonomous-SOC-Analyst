import uuid
from typing import BinaryIO, Optional, Tuple
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
        idempotency_key: Optional[str] = None,
        pipeline_version: Optional[str] = None,
        analysis_mode: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """
        Submits a file for background analysis.
        Returns a tuple of (job_id, reused).
        """
        job_id = str(uuid.uuid4())
        reused = False

        with self.uow:
            assert self.uow.session is not None
            # 1. Check idempotency if a key is provided
            if idempotency_key:
                job = self.uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
                if job:
                    if job.status == "queued" or job.status == "processing":
                        return str(job.id), True
                    elif job.status == "failed":
                        # Retry
                        job.status = "queued"  # type: ignore
                        job.queued_at = func.now()  # type: ignore
                        job.reused_count += 1  # type: ignore
                        job.last_requested_at = func.now()  # type: ignore
                        self.uow.session.commit()
                        
                        # Note: If retrying a failed job that already has the file staged, 
                        # we might need to handle the file upload again or assume it was removed.
                        # The client is re-uploading, so we stage the new file over the old job_id.
                        staged_path, file_sha256 = self.staging_store.stage_file(stream, str(job.id), original_filename)
                        job.file_sha256 = file_sha256  # type: ignore
                        job.original_filename = original_filename  # type: ignore
                        self.uow.session.commit()
                        
                        return str(job.id), True
                    elif job.status == "completed":
                        job.reused_count += 1  # type: ignore
                        job.last_requested_at = func.now()  # type: ignore
                        self.uow.session.commit()
                        return str(job.id), True

            # 2. Stage the file (which gives us the SHA-256)
            staged_path, file_sha256 = self.staging_store.stage_file(stream, job_id, original_filename)

            # 3. Create a new IngestionJob
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
                if idempotency_key:
                    existing_job = self.uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
                    if existing_job:
                        self.staging_store.remove_file(job_id) # Clean up the newly staged file
                        return str(existing_job.id), True
                raise # Re-raise if it's not handled

        return job_id, reused
