from pydantic_settings import BaseSettings

class IngestionLimits(BaseSettings):
    MAX_UPLOAD_BYTES: int = 52428800  # 50 MB
    MAX_RECORD_BYTES: int = 1048576   # 1 MB
    MAX_RECORDS_PER_FILE: int = 500000
    MAX_PARSE_FAILURES_STORED: int = 1000
    MAX_RAW_PREVIEW_CHARS: int = 500
    INGESTION_CHUNK_SIZE: int = 1000
    INGESTION_TIMEOUT_SECONDS: int = 300

class IngestionError(Exception):
    """Base class for ingestion exceptions."""
    pass

class UnsupportedInputFormatError(IngestionError):
    pass

class InputTooLargeError(IngestionError):
    pass

class RecordTooLargeError(IngestionError):
    pass

class RecordLimitExceededError(IngestionError):
    pass

class InvalidEncodingError(IngestionError):
    pass

class MalformedRecordError(IngestionError):
    pass
