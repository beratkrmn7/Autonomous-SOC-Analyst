import logging
from typing import Type, List, Tuple, Union, Dict, Any, Optional
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.ingestion.models import ParserSelection

logger = logging.getLogger(__name__)

MIN_PARSER_CONFIDENCE = 0.75
PARSER_AMBIGUITY_DELTA = 0.05

class ParserRegistry:
    def __init__(self):
        self._parsers: List[Type[BaseLogParser]] = []
        
    def register(self, parser_cls: Type[BaseLogParser]) -> None:
        if parser_cls not in self._parsers:
            self._parsers.append(parser_cls)
            # Sort parsers by priority (higher priority first)
            self._parsers.sort(key=lambda p: p.priority, reverse=True)

    def get_candidates(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> List[Tuple[Type[BaseLogParser], ParserMatch]]:
        candidates = []
        for p_cls in self._parsers:
            try:
                match_result = p_cls.match(raw_record, context)
                if match_result.matched:
                    candidates.append((p_cls, match_result))
            except Exception as e:
                logger.error(f"Error calling match on {p_cls.name}: {e}")
        return candidates

    def select_parser(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserSelection:
        candidates = self.get_candidates(raw_record, context)
        all_candidate_names = [p_cls.name for p_cls, _ in candidates]
        
        if not candidates:
            return ParserSelection(
                parser_name=None,
                confidence=0.0,
                reason="No parser matched.",
                schema_fingerprint=context.schema_fingerprint,
                candidate_parsers=[]
            )

        # Sort primarily by confidence, secondarily by priority
        candidates.sort(key=lambda x: (x[1].confidence, x[0].priority), reverse=True)
        
        best_parser_cls, best_match = candidates[0]
        
        if best_match.confidence < MIN_PARSER_CONFIDENCE:
            return ParserSelection(
                parser_name=None,
                confidence=best_match.confidence,
                reason=f"Confidence {best_match.confidence} is below minimum {MIN_PARSER_CONFIDENCE}",
                schema_fingerprint=context.schema_fingerprint,
                candidate_parsers=all_candidate_names
            )
            
        # Check for ambiguity
        if len(candidates) > 1:
            second_parser_cls, second_match = candidates[1]
            if (best_match.confidence - second_match.confidence) <= PARSER_AMBIGUITY_DELTA:
                logger.warning(
                    f"Parser ambiguity detected between {best_parser_cls.name} "
                    f"and {second_parser_cls.name} for fingerprint {context.schema_fingerprint}."
                )

        return ParserSelection(
            parser_name=best_parser_cls.name,
            confidence=best_match.confidence,
            reason=best_match.reason,
            schema_fingerprint=context.schema_fingerprint,
            candidate_parsers=all_candidate_names
        )

# Global registry instance
default_registry = ParserRegistry()
