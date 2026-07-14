class ConfigurationError(Exception):
    """Raised when there is an issue with application configuration or environment variables."""
    pass

class ParserError(Exception):
    """Raised when an unrecoverable error occurs during parsing."""
    pass

class UnsupportedSchemaError(Exception):
    """Raised when a log format cannot be parsed by any available parser."""
    pass

class EvidenceValidationError(Exception):
    """Raised when evidence validation strictly fails processing."""
    pass

class LLMProviderError(Exception):
    """Raised when the LLM provider is unreachable or returns an error."""
    pass

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

class QueuePublishFailedError(Exception):
    """Raised when publishing a job to the task queue broker fails."""
    def __init__(self, job_id: str, error_code: str = "queue_publish_failed"):
        self.job_id = job_id
        self.error_code = error_code
        super().__init__(f"Failed to publish job {job_id} to queue broker.")

class RetryableJobError(Exception):
    """Raised for explicitly known temporary failures that should be retried."""
    pass

class PermanentJobError(Exception):
    """Raised for explicitly known permanent failures that should not be retried."""
    pass
