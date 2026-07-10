from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.parsers.registry import ParserRegistry, default_registry

from agent.parsers.mock_parser import MockParser
from agent.parsers.pf_firewall import PfFirewallParser
from agent.parsers.generic_json import GenericJsonParser
from agent.parsers.syslog import SyslogParser
from agent.parsers.cef import CEFParser

# Register default parsers
default_registry.register(MockParser)
default_registry.register(PfFirewallParser)
default_registry.register(GenericJsonParser)
default_registry.register(SyslogParser)
default_registry.register(CEFParser)
