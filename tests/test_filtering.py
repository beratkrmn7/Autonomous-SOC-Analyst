
from agent.filtering import EventFilter
from agent.schema import CanonicalLogEvent
def test_filtering():
    f = EventFilter()
    noise_ev = CanonicalLogEvent(event_id="1", action="pass", dst_port=80, bytes=1000, parser_name="test", parse_status="success")
    cand_ev = CanonicalLogEvent(event_id="2", action="block", dst_port=3389, parser_name="test", parse_status="success")
    res = f.filter_events([noise_ev, cand_ev])
    assert len(res.noise) == 1
    assert len(res.candidates) == 1
    assert res.metrics == {"total": 2, "noise": 1, "context": 0, "candidates": 1}


def test_normal_https_remains_probable_noise():
    event = CanonicalLogEvent(
        event_id="https",
        action="pass",
        dst_port=443,
        bytes=1200,
        parser_name="test",
        parse_status="parsed",
    )

    result = EventFilter().filter_events([event])

    assert [item.event_id for item in result.noise] == [event.event_id]


def test_normal_dns_remains_probable_noise():
    event = CanonicalLogEvent(
        event_id="dns",
        action="pass",
        dst_port=53,
        bytes=200,
        parser_name="test",
        parse_status="parsed",
    )

    result = EventFilter().filter_events([event])

    assert [item.event_id for item in result.noise] == [event.event_id]
