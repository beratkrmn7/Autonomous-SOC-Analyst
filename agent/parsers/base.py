from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Union, Dict, Any, Optional
from datetime import datetime
from agent.schema import CanonicalLogEvent

class ParseContext(BaseModel):
    source_name: str
    line_number: Optional[int] = None
    byte_offset: Optional[int] = None
    schema_fingerprint: Optional[str] = None
    observed_at: datetime

class ParserMatch(BaseModel):
    matched: bool
    confidence: float
    reason: str

class BaseLogParser(ABC):
    name: str
    version: str
    priority: int

    @classmethod
    @abstractmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        """Evaluate if this parser can handle the given raw_record."""
        ...

    @abstractmethod
    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        """Parse the raw_record into a CanonicalLogEvent."""
        ...
