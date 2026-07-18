import json
from pathlib import Path

from agent.ingestion.readers import detect_input_format
from agent.ingestion.models import InputFormat
from agent.ingestion.pipeline import IngestionPipeline

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


def test_long_first_record_jsonl_with_json_suffix(tmp_path: Path):
    path = tmp_path / "long-records.json"
    records = [
        {
            "deviceAction": "block",
            "src": "192.0.2.10",
            "dst": f"198.51.100.{index}",
            "destinationPort": 4567,
            "proto": "tcp",
            "tcpFlags": "S",
            "start": f"2026-07-10T09:54:0{index}+03:00",
            "padding": "x" * 1500,
        }
        for index in (1, 2)
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    result = IngestionPipeline().ingest_file(path)

    assert result.input_format == InputFormat.JSONL
    assert result.metrics.total_records == 2
    assert result.metrics.parsed_records == 2
