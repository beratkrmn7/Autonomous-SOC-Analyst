from agent.ingestion.validation import validate_and_normalize
from agent.schema import CanonicalLogEvent

def test_semantic_validation():
    evt = CanonicalLogEvent(event_id="1", parser_name="p", parse_status="parsed", src_ip="invalid_ip", dst_port=999999)
    evt = validate_and_normalize(evt)
    assert evt.parse_status == "semantically_invalid"
    assert len(evt.parse_warnings) >= 2
