"""T-B: the exposure disposition is a pure function of canonical facts."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.triage.disposition import (
    EvidenceStrength,
    classify_evidence_strength,
    derive_exposure_disposition,
)

from tests.fixtures.sanitized_real_log import (
    DNAT_DATABASE_EXPOSURE,
    DOCKER_EXPOSURE,
    REDIS_EXPOSURE_MULTI_PACKET,
    REDIS_EXPOSURE_SINGLE_SYN,
    SSH_SWEEP_PORT_22,
)


TZ = timezone(timedelta(hours=3))
REPO_ROOT = Path(__file__).resolve().parents[2]


def _incident(events, *, family="firewall_exposure", severity="medium") -> IncidentBundle:
    timestamps = [event.timestamp for event in events if event.timestamp]
    return IncidentBundle(
        incident_id="INC-EXP",
        incident_type="inbound_sensitive_service_allowed",
        incident_family=family,
        title="Externally allowed sensitive service",
        severity=severity,
        confidence=0.8,
        first_seen=min(timestamps) if timestamps else datetime.now(TZ),
        last_seen=max(timestamps) if timestamps else datetime.now(TZ),
        primary_entity=events[0].dst_ip if events else "unknown",
        target_entities=[],
        signal_ids=["SIG-1"],
        event_ids=[event.event_id for event in events],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id=event.event_id,
                quote="",
                reason="allowed inbound sensitive service",
                source="detection",
                original_fields={},
                correlation_context={},
            )
            for event in events
        ],
        metrics={},
        mitre_techniques=[],
        merge_key="exposure",
    )


# 1. Same canonical facts always produce the same disposition.
def test_same_canonical_facts_produce_identical_disposition() -> None:
    incident = _incident(list(SSH_SWEEP_PORT_22))
    first = derive_exposure_disposition(incident, list(SSH_SWEEP_PORT_22))
    # Reversed input ordering must not change anything.
    second = derive_exposure_disposition(incident, list(reversed(SSH_SWEEP_PORT_22)))
    assert first == second
    assert first.verdict == "suspicious_activity"
    assert first.severity == second.severity
    assert first.evidence_strength == second.evidence_strength


# 2. Results are stable across hash seeds.
def test_disposition_is_stable_across_hash_seeds() -> None:
    program = (
        "from tests.fixtures.sanitized_real_log import SSH_SWEEP_PORT_22, DOCKER_EXPOSURE;"
        "from tests.triage.test_exposure_disposition import _incident;"
        "from agent.triage.disposition import derive_exposure_disposition;"
        "events = list(SSH_SWEEP_PORT_22) + [DOCKER_EXPOSURE];"
        "d = derive_exposure_disposition(_incident(events), events);"
        "print(d.model_dump_json())"
    )
    outputs = []
    for seed in ("0", "1"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO_ROOT,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout.strip())
    assert outputs[0] == outputs[1]


# 3. The four single-packet port-22 records share one policy outcome while
#    keeping their distinct destinations and source ports.
def test_single_packet_ssh_records_share_one_deterministic_outcome() -> None:
    dispositions = [
        derive_exposure_disposition(_incident([event]), [event])
        for event in SSH_SWEEP_PORT_22
    ]
    assert len({d.verdict for d in dispositions}) == 1
    assert len({d.severity for d in dispositions}) == 1
    assert len({d.evidence_strength for d in dispositions}) == 1
    assert dispositions[0].verdict == "suspicious_activity"
    assert dispositions[0].severity == "medium"  # sensitive service + weak evidence

    # The underlying canonical facts stay distinct.
    assert len({event.dst_ip for event in SSH_SWEEP_PORT_22}) == 4
    assert len({event.src_port for event in SSH_SWEEP_PORT_22}) == 4
    assert {d.effective_destination_ip for d in dispositions} == {
        event.dst_ip for event in SSH_SWEEP_PORT_22
    }


# 4. A one-packet SYN is syn_only.
def test_one_packet_syn_is_syn_only() -> None:
    assert (
        classify_evidence_strength([REDIS_EXPOSURE_SINGLE_SYN])
        is EvidenceStrength.SYN_ONLY
    )


# 5. High packet counts are never syn_only, even with SYN-only flags.
@pytest.mark.parametrize(
    "event,expected_packets",
    [(DOCKER_EXPOSURE, 56), (REDIS_EXPOSURE_MULTI_PACKET, 122)],
)
def test_multi_packet_exposures_are_not_syn_only(event, expected_packets) -> None:
    assert event.packets == expected_packets
    assert event.tcp_flags == "S"
    strength = classify_evidence_strength([event])
    assert strength is not EvidenceStrength.SYN_ONLY
    assert strength is EvidenceStrength.MULTI_PACKET_UNIDIRECTIONAL


# 6. No exposure is downgraded to severity "none" for lack of model evidence.
def test_no_exposure_receives_severity_none() -> None:
    cases = [
        [REDIS_EXPOSURE_SINGLE_SYN],
        [DOCKER_EXPOSURE],
        [REDIS_EXPOSURE_MULTI_PACKET],
        [DNAT_DATABASE_EXPOSURE],
        list(SSH_SWEEP_PORT_22),
    ]
    for events in cases:
        disposition = derive_exposure_disposition(_incident(events), events)
        assert disposition.severity != "none"
        assert disposition.verdict == "suspicious_activity"
        assert disposition.representative_evidence_ids


def test_severity_matrix_matches_documented_policy() -> None:
    # critical management + weak evidence -> high
    assert (
        derive_exposure_disposition(
            _incident([REDIS_EXPOSURE_SINGLE_SYN]), [REDIS_EXPOSURE_SINGLE_SYN]
        ).severity
        == "high"
    )
    # critical management + multi-packet unidirectional -> high
    assert (
        derive_exposure_disposition(
            _incident([DOCKER_EXPOSURE]), [DOCKER_EXPOSURE]
        ).severity
        == "high"
    )
    # sensitive remote service + weak evidence -> medium
    assert (
        derive_exposure_disposition(
            _incident([SSH_SWEEP_PORT_22[0]]), [SSH_SWEEP_PORT_22[0]]
        ).severity
        == "medium"
    )
    # DNAT sensitive exposure -> at least high
    dnat = derive_exposure_disposition(
        _incident([DNAT_DATABASE_EXPOSURE]), [DNAT_DATABASE_EXPOSURE]
    )
    assert dnat.severity in {"high", "critical"}
    assert dnat.nat_observed is True


def test_bidirectional_requires_a_reply_not_a_long_duration() -> None:
    long_running_syn = REDIS_EXPOSURE_SINGLE_SYN.model_copy(
        update={"duration_ms": 900_000}
    )
    assert (
        classify_evidence_strength([long_running_syn]) is EvidenceStrength.SYN_ONLY
    )


def test_application_flags_yield_application_evidence() -> None:
    from tests.fixtures.sanitized_real_log import SSH_SWEEP_FILE0

    application_event = SSH_SWEEP_FILE0[2]  # flags "SAP", 5 packets
    assert (
        classify_evidence_strength([application_event])
        is EvidenceStrength.APPLICATION_EVIDENCE
    )


def test_empty_canonical_events_are_a_genuine_review_condition() -> None:
    incident = _incident(list(SSH_SWEEP_PORT_22))
    disposition = derive_exposure_disposition(incident, [])
    assert disposition.verdict == "needs_review"
    assert disposition.review_reason == "canonical_events_unavailable"
