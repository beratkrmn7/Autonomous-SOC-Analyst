import hashlib
from typing import Protocol, BinaryIO, Tuple
from pathlib import Path

class StagingError(Exception):
    pass

class FileStagingStore(Protocol):
    def stage_file(self, stream: BinaryIO, job_id: str, original_filename: str) -> Tuple[str, str]:
        """
        Stages a file for background processing.
        Returns a tuple of (staged_path, sha256_hash).
        """
        ...
        
    def get_file_path(self, job_id: str) -> str:
        """Returns the absolute path of the staged file."""
        ...
        
    def remove_file(self, job_id: str) -> None:
        """Removes a staged file and cleans up resources."""
        ...
        
    def move_file(self, src_job_id: str, dest_job_id: str) -> None:
        """Moves a staged file from one job ID to another."""
        ...

class LocalFileStagingStore:
    def __init__(self, staging_dir: str, max_size_bytes: int = 50 * 1024 * 1024):
        self.staging_dir = Path(staging_dir)
        self.max_size_bytes = max_size_bytes
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        
    def stage_file(self, stream: BinaryIO, job_id: str, original_filename: str) -> Tuple[str, str]:
        # Path traversal prevention: we only use the job_id (a UUID) as the filename
        # original_filename is ignored here for security, though the caller can save it to DB
        staged_path = self.staging_dir / job_id
        
        sha256_hash = hashlib.sha256()
        bytes_written = 0
        
        try:
            with open(staged_path, 'wb') as f:
                while chunk := stream.read(8192):
                    bytes_written += len(chunk)
                    if bytes_written > self.max_size_bytes:
                        raise StagingError(f"Upload exceeds maximum allowed size of {self.max_size_bytes} bytes")
                    f.write(chunk)
                    sha256_hash.update(chunk)
            
            return str(staged_path.absolute()), sha256_hash.hexdigest()
        except Exception as e:
            if staged_path.exists():
                staged_path.unlink()
            if isinstance(e, StagingError):
                raise
            raise StagingError(f"Failed to stage file: {str(e)}") from e

    def get_file_path(self, job_id: str) -> str:
        staged_path = self.staging_dir / job_id
        if not staged_path.exists():
            raise StagingError(f"Staged file not found for job {job_id}")
        return str(staged_path.absolute())

    def remove_file(self, job_id: str) -> None:
        staged_path = self.staging_dir / job_id
        try:
            if staged_path.exists():
                staged_path.unlink()
        except Exception:
            import logging
            logging.getLogger(__name__).warning("staging_cleanup_failed")

    def move_file(self, src_job_id: str, dest_job_id: str) -> None:
        src_path = self.staging_dir / src_job_id
        dest_path = self.staging_dir / dest_job_id
        if not src_path.exists():
            raise StagingError(f"Source file not found for job {src_job_id}")
        if dest_path.exists():
            dest_path.unlink()
        import shutil
        shutil.move(str(src_path), str(dest_path))
