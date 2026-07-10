from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field
from datetime import datetime
from agent.schema import CanonicalLogEvent

class InputFormat(str, Enum):
    JSONL = "jsonl"
    JSON_ARRAY = "json_array"
    JSON_OBJECT = "json_object"
    SYSLOG = "syslog"
    CEF = "cef"
    UNKNOWN = "unknown"

class ParseStatus(str, Enum):
    PARSED = "parsed"
    FAILED = "failed"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    SEMANTICALLY_INVALID = "semantically_invalid"
    SKIPPED_BY_LIMIT = "skipped_by_limit"

class RecordEnvelope(BaseModel):
    source_name: str
    source_type: Optional[str] = None
    line_number: Optional[int] = None
    byte_offset: Optional[int] = None
    raw_record: Union[Dict[str, Any], str]
    raw_record_hash: str
    schema_fingerprint: Optional[str] = None
    received_at: datetime

class ParseFailure(BaseModel):
    source_name: str
    line_number: Optional[int] = None
    byte_offset: Optional[int] = None
    parser_name: Optional[str] = None
    status: ParseStatus
    error_code: str
    message: str
    raw_record_hash: str
    raw_record_preview: Optional[str] = None

class ParserSelection(BaseModel):
    parser_name: Optional[str] = None
    confidence: float
    reason: str
    schema_fingerprint: Optional[str] = None
    candidate_parsers: List[str]

class IngestionMetrics(BaseModel):
    total_records: int = 0
    parsed_records: int = 0
    failed_records: int = 0
    unsupported_records: int = 0
    semantically_invalid_records: int = 0
    skipped_records: int = 0
    bytes_read: int = 0
    duration_ms: int = 0
    parser_counts: Dict[str, int] = Field(default_factory=dict)
    error_counts: Dict[str, int] = Field(default_factory=dict)

class IngestionResult(BaseModel):
    source_name: str
    input_format: InputFormat
    events: List[CanonicalLogEvent] = Field(default_factory=list)
    failures: List[ParseFailure] = Field(default_factory=list)
    metrics: IngestionMetrics = Field(default_factory=IngestionMetrics)
    warnings: List[str] = Field(default_factory=list)
