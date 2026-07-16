"""Database search filtering coverage with a CI-unique module name."""

from datetime import timedelta

import pytest

from tests.search.conftest import BASE_TIME


def ids(response, field):
    assert response.status_code == 200, response.text
    return [item[field] for item in response.json()["items"]]


def test_incident_status_filter(seeded_env):
    response = seeded_env.client.get("/api/v1/search/incidents", params={"status": "new"})
    assert ids(response, "incident_id") == ["incident-1"]


def test_incident_severity_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents", params={"severity": "low"}
    )
    assert ids(response, "incident_id") == ["incident-2"]


def test_multiple_status_values_use_or(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params=[("status", "new"), ("status", "needs_review")],
    )
    assert set(ids(response, "incident_id")) == {"incident-1", "incident-2"}


def test_different_filters_use_and(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params=[("status", "new"), ("severity", "high")],
    )
    assert ids(response, "incident_id") == ["incident-1"]
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params=[("status", "needs_review"), ("severity", "high")],
    )
    assert ids(response, "incident_id") == []


def test_incident_confidence_range_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params={"min_confidence": 0.6, "max_confidence": 0.8},
    )
    assert ids(response, "incident_id") == ["incident-3"]


def test_incident_date_range_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params={
            "created_at_from": (BASE_TIME - timedelta(days=2)).isoformat(),
            "created_at_to": BASE_TIME.isoformat(),
        },
    )
    assert ids(response, "incident_id") == ["incident-3", "incident-2"]


def test_primary_entity_exact_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents", params={"primary_entity": "192.0.2.10"}
    )
    assert ids(response, "incident_id") == ["incident-1"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("true", ["incident-1"]), ("false", ["incident-3", "incident-2"])],
)
def test_has_report_filter(seeded_env, value, expected):
    response = seeded_env.client.get(
        "/api/v1/search/incidents", params={"has_report": value}
    )
    assert ids(response, "incident_id") == expected


def test_validated_evidence_and_mitre_membership_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/incidents",
        params={"has_validated_evidence": "true", "mitre_technique": "T1046"},
    )
    assert ids(response, "incident_id") == ["incident-1"]


def test_event_source_ip_filter_and_ipv6_normalization(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events", params={"src_ip": "2001:0db8:0:0::1"}
    )
    assert ids(response, "event_id") == ["event-2"]


def test_event_destination_ip_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events", params={"dst_ip": "198.51.100.20"}
    )
    assert ids(response, "event_id") == ["event-3", "event-1"]


def test_event_port_and_protocol_filters_use_and(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events", params={"dst_port": 443, "protocol": "tcp"}
    )
    assert ids(response, "event_id") == ["event-1"]


def test_event_timestamp_range(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events",
        params={
            "timestamp_from": (BASE_TIME - timedelta(hours=2)).isoformat(),
            "timestamp_to": BASE_TIME.isoformat(),
        },
    )
    assert ids(response, "event_id") == ["event-3", "event-2"]


def test_event_association_and_context_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events",
        params={"incident_id": "incident-1", "is_context": "true"},
    )
    assert ids(response, "event_id") == ["event-2"]
    response = seeded_env.client.get(
        "/api/v1/search/events", params={"job_id": "job-2"}
    )
    assert ids(response, "event_id") == ["event-3"]


def test_signal_rule_and_severity_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/signals",
        params={"rule_id": "rule-ssh", "severity": "high"},
    )
    assert ids(response, "signal_id") == ["signal-1"]


def test_suppressed_signal_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/signals", params={"suppressed": "true"}
    )
    assert ids(response, "signal_id") == ["signal-2"]


def test_signal_associations_and_mitre_filter(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/signals",
        params={"incident_id": "incident-1", "mitre_technique": "T1046"},
    )
    assert ids(response, "signal_id") == ["signal-1"]


def test_job_status_and_mode_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/jobs", params={"status": "completed", "analysis_mode": "full"}
    )
    assert ids(response, "job_id") == ["job-1"]


def test_job_created_and_completed_date_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/jobs",
        params={
            "created_at_from": (BASE_TIME - timedelta(days=4)).isoformat(),
            "completed_at_to": (BASE_TIME - timedelta(days=1)).isoformat(),
        },
    )
    assert ids(response, "job_id") == ["job-2"]


def test_job_reused_cancelled_attempt_and_exact_filters(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/jobs",
        params={
            "reused": "true",
            "cancelled": "true",
            "min_attempt_count": 0,
            "source_name": "firewall-a",
        },
    )
    assert ids(response, "job_id") == ["job-3"]
