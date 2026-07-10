import logging
import time
import uuid
import traceback
from typing import Union, Iterable, Dict, Any, List
from pathlib import Path

from agent.config import get_settings
settings = get_settings()
from agent.schema import CanonicalLogEvent
from agent.ingestion.models import (
    InputFormat, ParseStatus, RecordEnvelope, ParseFailure, 
    ParserSelection, IngestionMetrics, IngestionResult
)
from agent.ingestion.limits import IngestionLimits, IngestionError, RecordLimitExceededError
from agent.ingestion.readers import (
    detect_input_format, iter_jsonl_records, iter_json_array_records, 
    iter_text_records, iter_input_records
)
from agent.ingestion.validation import validate_and_normalize
from agent.parsers.base import ParseContext
from agent.parsers.registry import ParserRegistry, default_registry

logger = logging.getLogger(__name__)

class IngestionPipeline:
    def __init__(self, registry: ParserRegistry = None, limits: IngestionLimits = None):
        self.registry = registry or default_registry
        self.limits = limits or settings.ingestion
        
    def _generate_event_id(self, envelope: RecordEnvelope) -> str:
        """Deterministically generate an event_id using source_name and raw_record_hash."""
        # We take short segments to keep event IDs manageable
        # EVT-{source_hash[:8]}-{record_hash[:8]}
        # E.g., EVT-a3b4c5d6-1f2e3d4c
        # To avoid collisions in identical lines in the same file, we append line_number
        src_hash = str(hash(envelope.source_name))[:8].replace("-", "0")
        rec_hash = envelope.raw_record_hash[:8]
        line = str(envelope.line_number or 0)
        return f"EVT-{src_hash}-{rec_hash}-{line}"

    def ingest_file(self, path: Union[str, Path]) -> IngestionResult:
        start_time = time.time()
        path_obj = Path(path)
        
        if not path_obj.exists() or not path_obj.is_file():
            raise FileNotFoundError(f"File not found: {path}")
            
        file_size = path_obj.stat().st_size
        if file_size > self.limits.MAX_UPLOAD_BYTES:
            raise ValueError(f"File {path_obj.name} exceeds MAX_UPLOAD_BYTES")
            
        with open(path_obj, "rb") as f:
            first_bytes = f.read(1024)
            
        input_format = detect_input_format(path_obj, first_bytes)
        
        result = IngestionResult(
            source_name=path_obj.name,
            input_format=input_format
        )
        
        if input_format == InputFormat.UNKNOWN:
            result.warnings.append("Unknown or binary file format detected.")
            return result
            
        try:
            if input_format == InputFormat.JSONL or input_format == InputFormat.JSON_OBJECT:
                record_iter = iter_jsonl_records(path_obj, self.limits)
            elif input_format == InputFormat.JSON_ARRAY:
                record_iter = iter_json_array_records(path_obj, self.limits)
            elif input_format in [InputFormat.SYSLOG, InputFormat.CEF]:
                record_iter = iter_text_records(path_obj, self.limits)
            else:
                record_iter = iter_text_records(path_obj, self.limits)
                
            self._process_records(record_iter, result)
            
        except RecordLimitExceededError as e:
            result.warnings.append(str(e))
        except IngestionError as e:
            result.warnings.append(f"Ingestion error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error ingesting {path_obj.name}: {e}")
            result.warnings.append(f"Internal error: {e}")
            
        result.metrics.duration_ms = int((time.time() - start_time) * 1000)
        return result

    def ingest_records(self, records: Iterable[Union[Dict[str, Any], str]], source_name: str = "api-batch") -> IngestionResult:
        start_time = time.time()
        result = IngestionResult(
            source_name=source_name,
            input_format=InputFormat.UNKNOWN
        )
        try:
            record_iter = iter_input_records(records, source_name, self.limits)
            self._process_records(record_iter, result)
        except RecordLimitExceededError as e:
            result.warnings.append(str(e))
        except Exception as e:
            logger.error(f"Unexpected error ingesting records: {e}")
            result.warnings.append(f"Internal error: {e}")
            
        result.metrics.duration_ms = int((time.time() - start_time) * 1000)
        return result

    def _process_records(self, record_iter: Iterable[RecordEnvelope], result: IngestionResult):
        for envelope in record_iter:
            result.metrics.total_records += 1
            
            context = ParseContext(
                source_name=envelope.source_name,
                line_number=envelope.line_number,
                byte_offset=envelope.byte_offset,
                schema_fingerprint=envelope.schema_fingerprint,
                observed_at=envelope.received_at
            )
            
            selection = self.registry.select_parser(envelope.raw_record, context)
            
            if not selection.parser_name:
                self._record_failure(result, envelope, ParseStatus.UNSUPPORTED_SCHEMA, "NO_PARSER", selection.reason)
                continue
                
            result.metrics.parser_counts[selection.parser_name] = result.metrics.parser_counts.get(selection.parser_name, 0) + 1
            
            # Retrieve parser class to instantiate
            parser_cls = next((p for p in self.registry._parsers if p.name == selection.parser_name), None)
            if not parser_cls:
                self._record_failure(result, envelope, ParseStatus.FAILED, "PARSER_NOT_FOUND", "Parser class not found in registry")
                continue
                
            parser = parser_cls()
            event_id = self._generate_event_id(envelope)
            
            try:
                event = parser.parse(envelope.raw_record, context, event_id)
                event = validate_and_normalize(event)
                
                if event.parse_status == ParseStatus.SEMANTICALLY_INVALID.value:
                    self._record_failure(
                        result, envelope, ParseStatus.SEMANTICALLY_INVALID, 
                        "SEMANTIC_ERROR", ", ".join(event.parse_warnings),
                        parser_name=selection.parser_name
                    )
                else:
                    result.events.append(event)
                    result.metrics.parsed_records += 1
                    
            except Exception as e:
                # Capture traceback for logging but don't expose to user
                logger.error(f"Parser {selection.parser_name} failed on line {envelope.line_number}: {e}\n{traceback.format_exc()}")
                self._record_failure(result, envelope, ParseStatus.FAILED, "PARSE_EXCEPTION", str(e), parser_name=selection.parser_name)

    def _record_failure(
        self, 
        result: IngestionResult, 
        envelope: RecordEnvelope, 
        status: ParseStatus, 
        error_code: str, 
        message: str,
        parser_name: str = None
    ):
        if status == ParseStatus.UNSUPPORTED_SCHEMA:
            result.metrics.unsupported_records += 1
        elif status == ParseStatus.SEMANTICALLY_INVALID:
            result.metrics.semantically_invalid_records += 1
        else:
            result.metrics.failed_records += 1
            
        result.metrics.error_counts[error_code] = result.metrics.error_counts.get(error_code, 0) + 1
        
        if len(result.failures) < self.limits.MAX_PARSE_FAILURES_STORED:
            raw_str = str(envelope.raw_record)
            preview = raw_str[:self.limits.MAX_RAW_PREVIEW_CHARS] + ("..." if len(raw_str) > self.limits.MAX_RAW_PREVIEW_CHARS else "")
            
            result.failures.append(ParseFailure(
                source_name=envelope.source_name,
                line_number=envelope.line_number,
                byte_offset=envelope.byte_offset,
                parser_name=parser_name,
                status=status,
                error_code=error_code,
                message=message,
                raw_record_hash=envelope.raw_record_hash,
                raw_record_preview=preview
            ))
