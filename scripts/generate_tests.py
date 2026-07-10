import os

test_files = {
    "test_input_format_detection.py": '''import pytest
from pathlib import Path
from agent.ingestion.readers import detect_input_format
from agent.ingestion.models import InputFormat

def test_jsonl_detection():
    assert detect_input_format(Path("test.jsonl"), b'{"a": 1}\\n{"b": 2}') == InputFormat.JSONL

def test_json_array_detection():
    assert detect_input_format(Path("test.json"), b'[{"a": 1}]') == InputFormat.JSON_ARRAY

def test_syslog_detection():
    assert detect_input_format(Path("test.log"), b'<34>Oct 11 22:14:15 host test') == InputFormat.SYSLOG

def test_cef_detection():
    assert detect_input_format(Path("test.log"), b'CEF:0|Vendor|Prod') == InputFormat.CEF

def test_binary_detection():
    assert detect_input_format(Path("test.bin"), b'\\x00\\x01\\x02') == InputFormat.UNKNOWN
''',

    "test_streaming_jsonl_reader.py": '''import pytest
from pathlib import Path
from agent.ingestion.readers import iter_jsonl_records
from agent.ingestion.limits import IngestionLimits

def test_streaming_jsonl(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\\n{"b": 2}\\ninvalid\\n{"c": 3}')
    limits = IngestionLimits()
    records = list(iter_jsonl_records(p, limits))
    assert len(records) == 3
    assert records[0].raw_record["a"] == 1
    assert records[1].raw_record["b"] == 2
    assert records[2].raw_record["c"] == 3
''',

    "test_json_array_reader.py": '''import pytest
from pathlib import Path
from agent.ingestion.readers import iter_json_array_records
from agent.ingestion.limits import IngestionLimits

def test_json_array(tmp_path):
    p = tmp_path / "test.json"
    p.write_text('[{"a": 1}, {"b": 2}]')
    limits = IngestionLimits()
    records = list(iter_json_array_records(p, limits))
    assert len(records) == 2
    assert records[0].raw_record["a"] == 1
''',

    "test_ingestion_limits.py": '''import pytest
from pathlib import Path
from agent.ingestion.readers import iter_jsonl_records
from agent.ingestion.limits import IngestionLimits
from agent.errors import RecordLimitExceededError

def test_record_limit(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\\n{"b": 2}\\n{"c": 3}')
    limits = IngestionLimits(MAX_RECORDS_PER_FILE=2)
    with pytest.raises(RecordLimitExceededError):
        list(iter_jsonl_records(p, limits))

def test_record_bytes_limit(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\\n{"long": "' + 'A'*2000 + '"}\\n{"c": 3}')
    limits = IngestionLimits(MAX_RECORD_BYTES=1000)
    records = list(iter_jsonl_records(p, limits))
    assert len(records) == 2 # Skips the long one
''',

    "test_schema_fingerprint.py": '''import pytest
from agent.ingestion.fingerprint import get_schema_fingerprint

def test_json_fingerprint():
    fp1 = get_schema_fingerprint({"b": 2, "a": 1})
    fp2 = get_schema_fingerprint({"a": 9, "b": 5})
    assert fp1 == fp2

def test_different_json_fingerprint():
    fp1 = get_schema_fingerprint({"a": 1})
    fp2 = get_schema_fingerprint({"c": 3})
    assert fp1 != fp2
''',

    "test_parser_registry.py": '''import pytest
from agent.parsers.registry import ParserRegistry
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent

class DummyParser1(BaseLogParser):
    name = "dummy1"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.8, reason="")
    def parse(self, raw, ctx, evt): return None

class DummyParser2(BaseLogParser):
    name = "dummy2"
    version = "1"
    priority = 20
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.8, reason="")
    def parse(self, raw, ctx, evt): return None

def test_parser_priority():
    reg = ParserRegistry()
    reg.register(DummyParser1)
    reg.register(DummyParser2)
    sel = reg.select_parser({}, ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"))
    assert sel.parser_name == "dummy2" # Higher priority
''',

    "test_parser_ambiguity.py": '''import pytest
from agent.parsers.registry import ParserRegistry
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch

class DummyParser1(BaseLogParser):
    name = "dummy1"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.9, reason="")
    def parse(self, raw, ctx, evt): return None

class DummyParser2(BaseLogParser):
    name = "dummy2"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.88, reason="")
    def parse(self, raw, ctx, evt): return None

def test_parser_ambiguity(caplog):
    reg = ParserRegistry()
    reg.register(DummyParser1)
    reg.register(DummyParser2)
    sel = reg.select_parser({}, ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"))
    assert "Parser ambiguity detected" in caplog.text
''',

    "test_pf_firewall_parser.py": '''import pytest
from agent.parsers.pf_firewall import PfFirewallParser
from agent.parsers.base import ParseContext

def test_pf_firewall_parsing():
    raw = {"start": "2026-07-10T11:00:00Z", "src": "1.1.1.1", "deviceAction": "allow"}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.action == "pass"
    assert evt.src_ip == "1.1.1.1"

def test_pf_firewall_optional_fields():
    # Should not fail if fields are missing
    raw = {"src": "1.1.1.1", "pf": "yes"}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
''',

    "test_generic_json_parser.py": '''import pytest
from agent.parsers.generic_json import GenericJsonParser
from agent.parsers.base import ParseContext

def test_generic_json_mapping():
    raw = {"client_ip": "1.1.1.1", "status": "deny"}
    p = GenericJsonParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
    assert evt.action == "deny"
''',

    "test_syslog_parser.py": '''import pytest
from agent.parsers.syslog import SyslogParser
from agent.parsers.base import ParseContext

def test_rfc5424():
    raw = "<165>1 2026-07-10T09:51:40+03:00 host app 1234 ID47 - message"
    p = SyslogParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.raw_message == "message"
    assert evt.timestamp is not None
''',

    "test_cef_parser.py": '''import pytest
from agent.parsers.cef import CEFParser
from agent.parsers.base import ParseContext

def test_cef_parsing():
    raw = "CEF:0|Vendor|Prod|1.0|1|name|5|src=1.1.1.1 act=block msg=hello escaped\\\\=pipe"
    p = CEFParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
    assert evt.action == "block"
    assert evt.raw_message == "hello escaped=pipe"
''',

    "test_timestamp_normalization.py": '''import pytest
from agent.parsers.helpers import normalize_timestamp
from datetime import timezone

def test_iso8601():
    dt = normalize_timestamp("2026-07-10T10:00:00Z")
    assert dt.year == 2026
    assert dt.tzinfo == timezone.utc

def test_unix_seconds():
    dt = normalize_timestamp("1672531200")
    assert dt.year == 2023

def test_invalid():
    assert normalize_timestamp("invalid") is None
''',

    "test_semantic_validation.py": '''import pytest
from agent.ingestion.validation import validate_and_normalize
from agent.schema import CanonicalLogEvent

def test_semantic_validation():
    evt = CanonicalLogEvent(event_id="1", parser_name="p", parse_status="parsed", src_ip="invalid_ip", dst_port=999999)
    evt = validate_and_normalize(evt)
    assert evt.parse_status == "semantically_invalid"
    assert len(evt.parse_warnings) >= 2
''',

    "test_mixed_format_ingestion.py": '''import pytest
from pathlib import Path
from agent.ingestion.pipeline import IngestionPipeline

def test_mixed_formats():
    pipe = IngestionPipeline()
    res = pipe.ingest_file("tests/fixtures/mixed/mixed_formats.log")
    assert res.metrics.total_records == 5
    # 4 valid, 1 invalid
    assert res.metrics.parsed_records == 4
    assert res.metrics.failed_records + res.metrics.unsupported_records == 1
    assert "mock_json" in res.metrics.parser_counts
    assert "syslog" in res.metrics.parser_counts
    assert "cef" in res.metrics.parser_counts
''',

    "test_parse_failure_isolation.py": '''import pytest
from agent.ingestion.pipeline import IngestionPipeline

def test_failure_isolation():
    pipe = IngestionPipeline()
    res = pipe.ingest_records([
        '{"deviceAction": "allow", "src": "1.1.1.1", "proto": "tcp"}',
        '{"invalid_json":',
        '{"deviceAction": "allow", "src": "2.2.2.2", "proto": "tcp"}'
    ], source_name="test")
    assert res.metrics.total_records == 3
    assert res.metrics.parsed_records == 2
''',

    "test_event_id_stability.py": '''import pytest
from agent.ingestion.pipeline import IngestionPipeline

def test_event_id_stability():
    pipe = IngestionPipeline()
    res1 = pipe.ingest_records(['{"src": "1.1.1.1", "action": "allow"}'], source_name="t")
    res2 = pipe.ingest_records(['{"src": "1.1.1.1", "action": "allow"}'], source_name="t")
    assert res1.events[0].event_id == res2.events[0].event_id
''',

    "test_ingestion_input_immutability.py": '''import pytest
from agent.ingestion.pipeline import IngestionPipeline

def test_immutability():
    raw = {"src": "1.1.1.1", "action": "allow"}
    raw_copy = dict(raw)
    pipe = IngestionPipeline()
    pipe.ingest_records([raw], source_name="t")
    assert raw == raw_copy
''',

    "test_ingest_cli.py": '''import pytest
import subprocess

def test_cli_ingest_mode():
    res = subprocess.run(["python", "main.py", "--ingest-file", "tests/fixtures/mock/mock_events.jsonl"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "INGESTION SUMMARY" in res.stdout
''',
    
    "test_mock_parser.py": '''import pytest
from agent.parsers.mock_parser import MockParser
from agent.parsers.base import ParseContext

def test_mock_parser():
    p = MockParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    raw = {"parser_name": "mock", "src_ip": "1.1.1.1"}
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "1")
    assert evt.src_ip == "1.1.1.1"
'''
}

os.makedirs("tests", exist_ok=True)
for name, content in test_files.items():
    with open(os.path.join("tests", name), "w") as f:
        f.write(content)

print("Tests created successfully.")
