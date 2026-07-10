from pathlib import Path
from agent.ingestion.readers import detect_input_format
from agent.ingestion.models import InputFormat

def test_jsonl_detection():
    assert detect_input_format(Path("test.jsonl"), b'{"a": 1}\n{"b": 2}') == InputFormat.JSONL

def test_json_array_detection():
    assert detect_input_format(Path("test.json"), b'[{"a": 1}]') == InputFormat.JSON_ARRAY

def test_syslog_detection():
    assert detect_input_format(Path("test.log"), b'<34>Oct 11 22:14:15 host test') == InputFormat.SYSLOG

def test_cef_detection():
    assert detect_input_format(Path("test.log"), b'CEF:0|Vendor|Prod') == InputFormat.CEF

def test_binary_detection():
    assert detect_input_format(Path("test.bin"), b'\x00\x01\x02') == InputFormat.UNKNOWN
