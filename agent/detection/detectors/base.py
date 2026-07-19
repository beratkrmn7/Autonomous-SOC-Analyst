from typing import List, Sequence
from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel

from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal
from agent.detection.config import DetectionSettings
from agent.detection.contracts import DetectionRuleMetadata

class DetectionContext(BaseModel):
    settings: DetectionSettings
    analysis_started_at: datetime
    source_name: str = "default"

class BaseDetectionRule(ABC):
    metadata: DetectionRuleMetadata

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def version(self) -> str:
        return self.metadata.version

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def family(self) -> str:
        return self.metadata.family

    @property
    def priority(self) -> int:
        return self.metadata.priority

    @abstractmethod
    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> List[DetectionSignal]:
        pass
