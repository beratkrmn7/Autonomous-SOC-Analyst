import pytest
from typing import List, Any
from agent.config import Settings

class FakeRunnable:
    def __init__(self, actions: List[Any]):
        self.actions = actions
        self.call_count = 0
        self.last_messages: List[Any] = []
        
    def invoke(self, messages: List[Any], **kwargs):
        self.last_messages = messages
        if self.call_count >= len(self.actions):
            raise Exception("No more actions scripted")
            
        action = self.actions[self.call_count]
        self.call_count += 1
        
        if isinstance(action, Exception):
            raise action
            
        return action

class ScriptableFakeLLM:
    def __init__(self, actions: List[Any]):
        self.runnable = FakeRunnable(actions)
        self.last_tools: List[Any] = []
        
    def bind_tools(self, tools: List[Any], **kwargs):
        self.last_tools = tools
        return self.runnable

@pytest.fixture
def fake_llm():
    def _create(actions: List[Any]):
        return ScriptableFakeLLM(actions)
    return _create

@pytest.fixture
def triage_test_settings():
    return Settings(
        llm_enabled=True,
        groq_api_key=None,
        llm_max_retries=0,
        llm_retry_base_seconds=0.01,
        llm_retry_max_seconds=0.01,
    )
