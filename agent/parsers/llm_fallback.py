
import json
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq
from agent.schema import CanonicalLogEvent

import logging
logger = logging.getLogger(__name__)

class MappingConfig(BaseModel):
    timestamp_key: str = Field(default="", description="JSON key for timestamp")
    src_ip_key: str = Field(default="", description="JSON key for source IP")
    dst_ip_key: str = Field(default="", description="JSON key for destination IP")
    src_port_key: str = Field(default="", description="JSON key for source port")
    dst_port_key: str = Field(default="", description="JSON key for destination port")
    event_type_key: str = Field(default="", description="JSON key for event type")
    action_key: str = Field(default="", description="JSON key for action taken")
    raw_message_key: str = Field(default="", description="JSON key for raw message, if any")

class LLMParserAssistant:
    def __init__(self):
        # We use a low temperature for strict schema generation
        self.llm = None
        self.structured_llm = None
        
    def _init_llm(self):
        if self.structured_llm:
            return
        from agent.config import get_settings
        from agent.errors import ConfigurationError
        settings = get_settings()
        if not settings.llm_enabled or not settings.llm_parser_fallback_enabled:
            raise ConfigurationError("LLM parser fallback is disabled in settings.")
        if not settings.groq_api_key:
            raise ConfigurationError("Missing API key for LLM fallback.")
            
        self.llm = ChatGroq(
            model="llama-3.1-70b-versatile", 
            temperature=0, 
            api_key=settings.groq_api_key.get_secret_value() if settings.groq_api_key else None  # type: ignore
        )
        self.structured_llm = self.llm.with_structured_output(MappingConfig)
        
    def propose_mapping(self, sample_logs: List[Dict[str, Any]]) -> MappingConfig:
        """
        Uses an LLM to propose a key-mapping configuration for unknown log formats.
        """
        samples_str = json.dumps(sample_logs[:3], indent=2)
        system_prompt = """You are an expert SIEM Log Integration Engineer. 
You are given a few samples of an unknown JSON log format. 
Your task is to identify which JSON keys map to our Canonical Schema fields.
If a field doesn't exist in the JSON, leave the key as empty string "".
Do NOT invent keys, only use exactly what is in the JSON.
"""
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Sample Logs:\n{samples_str}")
        ]
        
        try:
            self._init_llm()
            if not self.structured_llm:
                return MappingConfig()
            mapping = self.structured_llm.invoke(messages)
            return mapping or MappingConfig()
        except Exception as e:
            logger.error(f"Error generating LLM fallback mapping: {e}")
            return MappingConfig()
            
    def parse_with_mapping(self, raw_log: Dict[str, Any], mapping: MappingConfig) -> CanonicalLogEvent:
        """
        Parses a log using the LLM-proposed mapping configuration.
        """
        # Simple extraction helper
        def get_val(key):
            if not key:
                return None
            # support simple dot notation (e.g. source.ip)
            parts = key.split('.')
            val: Any = raw_log
            for p in parts:
                if isinstance(val, dict):
                    val = val.get(p)
                else:
                    return None
            return val
            
        src_ip = get_val(mapping.src_ip_key)
        dst_ip = get_val(mapping.dst_ip_key)
        src_port = get_val(mapping.src_port_key)
        dst_port = get_val(mapping.dst_port_key)
        event_type = get_val(mapping.event_type_key)
        raw_message = get_val(mapping.raw_message_key)
        
        if not raw_message:
            # Fallback construct
            raw_message = json.dumps(raw_log)
            
        return CanonicalLogEvent(
            timestamp=None,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=int(src_port) if src_port is not None else None,
            dst_port=int(dst_port) if dst_port is not None else None,
            event_type=str(event_type) if event_type else None,
            raw_message=str(raw_message),
            original_log=raw_log,
            event_id=raw_log.get("event_id") or "UNKNOWN",
            parser_name="llm_fallback",
            parse_status="success"
        )
