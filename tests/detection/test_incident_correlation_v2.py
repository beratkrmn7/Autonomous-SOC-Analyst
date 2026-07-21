"""Focused tests for Phase 6E.2 - Incident Correlation V2.

Covers the required behaviors: cross-rule signals with strong shared-event
evidence become one incident, precedence chooses the anchor deterministically,
supporting signals stay visible and attached, clustering never over-merges
transitively, incident identity is stable, and routing/reporting runs once
per correlated incident (fresh and hydrated).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.detection.config import DetectionSettings
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.coordinated_scan import RepeatedBlockedScannerRule
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.inbound_exposure import (
    CriticalManagementServiceExposedRule,
    DnatSensitiveServiceExposureRule,
    WanToLanSensitiveServiceAllowedRule,
)
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.engine import DetectionEngine
from agent.detection.incident_correlation import (
    build_correlated_incident,
    cluster_signals,
    event_overlap_ratio,
    time_windows_are_compatible,
)
from agent.detection.models import DetectionEvidence, DetectionSignal
from agent.detection.registry import RuleRegistry, default_registry
from agent.persistence.database import Base
from agent.persistence.orm_models import IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.triage.routing import decide_route
from tests.detection.helpers import FIXED_TIME, build_event


ENTITY = "203.0.113.9"


def _signal(
    signal_id: str,
    rule_id: str,
    signal_type: str,
    signal_family: str,
    event_ids: list[str],
    *,
    severity: str = "medium",
    confidence: float = 0.7,
    first_seen: datetime = FIXED_TIME,
    last_seen: datetime | None = None,
    primary_entity: str = ENTITY,
    target_entities: list[str] | None = None,
    evidence: list[DetectionEvidence] | None = None,
    mitre_techniques: list[str] | None = None,
) -> DetectionSignal:
    return DetectionSignal(
        signal_id=signal_id,
        rule_id=rule_id,
        rule_version="1.0.0",
        rule_name=rule_id.replace("_", " ").title(),
        signal_type=signal_type,
        signal_family=signal_family,
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen or first_seen,
        event_ids=event_ids,
        primary_entity=primary_entity,
        target_entities=target_entities or [],
        metrics={},
        evidence=evidence or [],
        mitre_techniques=mitre_techniques or [],
        tags=[],
    )


def _evidence(event_id: str) -> DetectionEvidence:
    return DetectionEvidence(
        event_id=event_id,
        quote="deterministic test evidence",
        reason="test",
        source="test",
        original_fields={},
        correlation_context={},
    )


# ---------------------------------------------------------------------------
# 2. Event-overlap calculation
# ---------------------------------------------------------------------------


def test_event_overlap_ratio_matches_worked_examples() -> None:
    seven_of_seven_and_ten = _signal(
        "s1", "r1", "t1", "f1", [f"e{i}" for i in range(7)]
    )
    ten_events = _signal("s2", "r2", "t2", "f2", [f"e{i}" for i in range(10)])
    assert event_overlap_ratio(seven_of_seven_and_ten, ten_events) == 1.0

    five_events = _signal("s3", "r3", "t3", "f3", [f"e{i}" for i in range(5)])
    eight_sharing_four = _signal(
        "s4", "r4", "t4", "f4", [f"e{i}" for i in range(4)] + ["x1", "x2", "x3", "x4"]
    )
    assert event_overlap_ratio(five_events, eight_sharing_four) == pytest.approx(0.8)

    eight_sharing_three = _signal(
        "s5", "r5", "t5", "f5", [f"e{i}" for i in range(3)] + ["y1", "y2", "y3", "y4", "y5"]
    )
    assert event_overlap_ratio(five_events, eight_sharing_three) == pytest.approx(0.6)


def test_event_overlap_ratio_is_zero_for_empty_event_set() -> None:
    empty = _signal("s1", "r1", "t1", "f1", [])
    other = _signal("s2", "r2", "t2", "f2", ["e1"])
    assert event_overlap_ratio(empty, other) == 0.0
    assert event_overlap_ratio(other, empty) == 0.0


# ---------------------------------------------------------------------------
# 3. Time compatibility
# ---------------------------------------------------------------------------


def test_time_windows_compatible_across_old_bucket_boundary() -> None:
    window_seconds = 300
    seconds_into_bucket = int(FIXED_TIME.timestamp()) % window_seconds
    seconds_to_boundary = window_seconds - seconds_into_bucket
    if seconds_to_boundary < 2:
        seconds_to_boundary += window_seconds

    just_before_boundary = FIXED_TIME + timedelta(seconds=seconds_to_boundary - 1)
    just_after_boundary = just_before_boundary + timedelta(seconds=2)

    def bucket(ts: datetime) -> int:
        return int(ts.timestamp()) // window_seconds

    assert bucket(just_before_boundary) != bucket(just_after_boundary)

    left = _signal(
        "s1", "r1", "t1", "f1", ["e1"], first_seen=just_before_boundary
    )
    right = _signal(
        "s2", "r2", "t2", "f2", ["e1"], first_seen=just_after_boundary
    )
    assert time_windows_are_compatible(left, right, window_seconds) is True


def test_time_windows_incompatible_beyond_merge_window() -> None:
    left = _signal("s1", "r1", "t1", "f1", ["e1"], first_seen=FIXED_TIME)
    right = _signal(
        "s2", "r2", "t2", "f2", ["e1"], first_seen=FIXED_TIME + timedelta(seconds=301)
    )
    assert time_windows_are_compatible(left, right, 300) is False


# ---------------------------------------------------------------------------
# 4 & 8 & 9. Correlation eligibility (event overlap, no speculative merging)
# ---------------------------------------------------------------------------


def test_overlap_below_threshold_leaves_incidents_separate() -> None:
    five_events = _signal(
        "s-anchor", "rdp_probe", "rdp_probe", "service_probing",
        [f"e{i}" for i in range(5)],
    )
    eight_sharing_three = _signal(
        "s-other", "network_scan_horizontal", "horizontal_scan", "network_scanning",
        [f"e{i}" for i in range(3)] + ["y1", "y2", "y3", "y4", "y5"],
    )
    clusters = cluster_signals(
        [five_events, eight_sharing_three], window_seconds=300, overlap_threshold=0.70
    )
    assert len(clusters) == 2


def test_same_source_same_time_no_shared_events_stay_separate() -> None:
    a = _signal("s1", "rdp_probe", "rdp_probe", "service_probing", ["e1", "e2"])
    b = _signal(
        "s2",
        "network_scan_horizontal",
        "horizontal_scan",
        "network_scanning",
        ["e3", "e4"],
    )
    clusters = cluster_signals([a, b], window_seconds=300, overlap_threshold=0.70)
    assert len(clusters) == 2


# ---------------------------------------------------------------------------
# 5. Deterministic clustering without transitive over-merging
# ---------------------------------------------------------------------------


def test_transitive_bridge_does_not_over_merge() -> None:
    # A-B overlap 0.8, B-C overlap 0.8, A-C overlap 0.6 (below threshold).
    a = _signal(
        "sig-a", "rdp_probe", "rdp_probe", "service_probing",
        [f"e{i}" for i in range(1, 9)],  # e1..e8
    )
    b = _signal(
        "sig-b", "network_scan_horizontal", "horizontal_scan", "network_scanning",
        ["e5", "e6", "e7", "e8", "e9"],
    )
    c = _signal(
        "sig-c", "repeated_blocked_scanner", "repeated_blocked_scanner", "network_scanning",
        ["e6", "e7", "e8", "e9", "e10"],
    )
    assert event_overlap_ratio(a, b) == pytest.approx(0.8)
    assert event_overlap_ratio(b, c) == pytest.approx(0.8)
    assert event_overlap_ratio(a, c) == pytest.approx(0.6)

    clusters = cluster_signals([a, b, c], window_seconds=300, overlap_threshold=0.70)

    assert len(clusters) == 2
    anchor_cluster = next(cl for cl in clusters if cl[0].signal_id == "sig-a")
    assert {s.signal_id for s in anchor_cluster} == {"sig-a", "sig-b"}
    other_cluster = next(cl for cl in clusters if cl[0].signal_id == "sig-c")
    assert [s.signal_id for s in other_cluster] == ["sig-c"]


# ---------------------------------------------------------------------------
# 6 & 7. Primary incident precedence
# ---------------------------------------------------------------------------


def test_sequence_ending_in_allowed_connection_wins_over_horizontal_scan() -> None:
    sequence = _signal(
        "sig-seq",
        "scan_followed_by_allowed_connection",
        "scan_followed_by_allowed_connection",
        "network_intrusion_candidate",
        ["e1", "e2", "e3"],
        severity="high",
    )
    scan = _signal(
        "sig-scan", "network_scan_horizontal", "horizontal_scan", "network_scanning",
        ["e1", "e2", "e3"],
        severity="medium",
    )
    clusters = cluster_signals([scan, sequence], window_seconds=300, overlap_threshold=0.70)

    assert len(clusters) == 1
    assert clusters[0][0].signal_id == "sig-seq"


def test_critical_management_exposure_wins_over_dnat_exposure() -> None:
    critical = _signal(
        "sig-critical",
        "critical_management_service_exposed",
        "critical_management_service_exposed",
        "firewall_exposure",
        ["e1", "e2"],
        severity="critical",
    )
    dnat = _signal(
        "sig-dnat",
        "dnat_sensitive_service_exposure",
        "dnat_sensitive_service_exposure",
        "firewall_exposure",
        ["e1", "e2"],
        severity="high",
    )
    clusters = cluster_signals([dnat, critical], window_seconds=300, overlap_threshold=0.70)

    assert len(clusters) == 1
    anchor = clusters[0][0]
    assert anchor.signal_id == "sig-critical"
    incident = build_correlated_incident(clusters[0], {}, [], DetectionSettings())
    assert incident.incident_type == "critical_management_service_exposed"
    assert set(incident.signal_ids) == {"sig-critical", "sig-dnat"}


# ---------------------------------------------------------------------------
# 9 (ID stability), 12 (order invariance), 13 (stable ID) - incident assembly
# ---------------------------------------------------------------------------


def test_reversed_signal_order_produces_identical_incident() -> None:
    a = _signal(
        "sig-a", "rdp_probe", "rdp_probe", "service_probing",
        ["e1", "e2", "e3"], evidence=[_evidence("e1")],
    )
    b = _signal(
        "sig-b", "network_scan_horizontal", "horizontal_scan", "network_scanning",
        ["e1", "e2", "e3"], evidence=[_evidence("e2")],
    )
    c = _signal(
        "sig-c", "repeated_blocked_scanner", "repeated_blocked_scanner", "network_scanning",
        ["e1", "e2", "e3"], evidence=[_evidence("e3")],
    )
    settings = DetectionSettings()

    forward_clusters = cluster_signals(
        [a, b, c], window_seconds=300, overlap_threshold=0.70
    )
    reversed_clusters = cluster_signals(
        [c, b, a], window_seconds=300, overlap_threshold=0.70
    )
    assert len(forward_clusters) == len(reversed_clusters) == 1

    forward_incident = build_correlated_incident(forward_clusters[0], {}, [], settings)
    reversed_incident = build_correlated_incident(reversed_clusters[0], {}, [], settings)

    assert forward_incident.model_dump(mode="json") == reversed_incident.model_dump(
        mode="json"
    )
    assert forward_incident.incident_type == "rdp_probe"


def test_adding_absorbed_signal_does_not_change_incident_id() -> None:
    anchor = _signal(
        "sig-anchor", "rdp_probe", "rdp_probe", "service_probing", ["e1", "e2"]
    )
    absorbed = _signal(
        "sig-absorbed",
        "network_scan_horizontal",
        "horizontal_scan",
        "network_scanning",
        ["e1", "e2"],
    )
    settings = DetectionSettings()

    anchor_only = build_correlated_incident([anchor], {}, [], settings)
    with_absorbed = build_correlated_incident([anchor, absorbed], {}, [], settings)

    assert anchor_only.incident_id == with_absorbed.incident_id
    assert anchor_only.merge_key == with_absorbed.merge_key
    assert with_absorbed.absorbed_signal_ids == ["sig-absorbed"]
    assert "sig-anchor" not in with_absorbed.absorbed_signal_ids


def test_two_anchors_same_source_same_window_get_different_incident_ids() -> None:
    anchor_one = _signal(
        "sig-one", "rdp_probe", "rdp_probe", "service_probing", ["e1", "e2"]
    )
    anchor_two = _signal(
        "sig-two", "ssh_probe", "ssh_probe", "service_probing", ["e3", "e4"]
    )
    settings = DetectionSettings()

    incident_one = build_correlated_incident([anchor_one], {}, [], settings)
    incident_two = build_correlated_incident([anchor_two], {}, [], settings)

    assert incident_one.incident_id != incident_two.incident_id


# ---------------------------------------------------------------------------
# 17. Evidence bounded, unique, owned by incident events
# ---------------------------------------------------------------------------


def test_evidence_is_bounded_unique_and_owned_by_incident_events() -> None:
    signals = []
    for i in range(4):
        event_ids = [f"e{i}-{j}" for j in range(4)]
        signals.append(
            _signal(
                f"sig-{i}",
                "rdp_probe" if i == 0 else f"rule-{i}",
                "rdp_probe" if i == 0 else f"type-{i}",
                "service_probing",
                event_ids,
                evidence=[_evidence(eid) for eid in event_ids]
                + [_evidence("not-an-incident-event")],
            )
        )
    settings = DetectionSettings()
    incident = build_correlated_incident(signals, {}, [], settings)

    assert len(incident.evidence) <= 10
    event_ids_seen = [item.event_id for item in incident.evidence]
    assert len(event_ids_seen) == len(set(event_ids_seen))
    incident_event_id_set = set(incident.event_ids)
    assert all(eid in incident_event_id_set for eid in event_ids_seen)
    assert "not-an-incident-event" not in event_ids_seen


# ---------------------------------------------------------------------------
# 1-4, 14-16: engine-level correlation of real detection signals
# ---------------------------------------------------------------------------


def _scoped_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    registry.register(HorizontalScanRule())
    registry.register(RepeatedBlockedScannerRule())
    return registry


def _scoped_settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "REMOTE_SERVICE_MIN_EVENTS": 4,
        "REMOTE_SERVICE_MIN_DISTINCT_TARGETS": 4,
        "HORIZONTAL_SCAN_MIN_EVENTS": 4,
        "HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS": 4,
        "REPEATED_BLOCKED_SCANNER_MIN_EVENTS": 4,
        "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS": 2,
        "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS": 2,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def _correlated_probe_events(count: int = 4, prefix: str = "corr") -> list:
    return [
        build_event(
            f"{prefix}-{i}",
            timestamp=FIXED_TIME + timedelta(seconds=i),
            src_ip=ENTITY,
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=3389,
            protocol="TCP",
            action="block",
            tcp_flags="SYN",
        )
        for i in range(count)
    ]


def test_rdp_probe_and_repeated_blocked_scanner_become_one_incident() -> None:
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    registry.register(RepeatedBlockedScannerRule())
    events = _correlated_probe_events()

    result = DetectionEngine(registry=registry, settings=_scoped_settings()).analyze(events)

    assert {signal.signal_type for signal in result.signals} == {
        "rdp_probe",
        "repeated_blocked_scanner",
    }
    assert len(result.incidents) == 1
    assert result.incidents[0].incident_type == "rdp_probe"


def test_three_rule_correlation_produces_one_incident_with_all_signals() -> None:
    events = _correlated_probe_events()

    result = DetectionEngine(
        registry=_scoped_registry(), settings=_scoped_settings()
    ).analyze(events)

    # 14: all cross-rule signals remain in DetectionResult.signals.
    assert len(result.signals) == 3
    assert {s.signal_type for s in result.signals} == {
        "rdp_probe",
        "horizontal_scan",
        "repeated_blocked_scanner",
    }

    # 2/5: rdp_probe (service-specific) wins the single correlated incident.
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.incident_type == "rdp_probe"

    # 3: every signal ID remains attached.
    all_signal_ids = {s.signal_id for s in result.signals}
    assert set(incident.signal_ids) == all_signal_ids

    # 4: the two non-primary signals are recorded as absorbed.
    rdp_signal_id = next(
        s.signal_id for s in result.signals if s.signal_type == "rdp_probe"
    )
    assert rdp_signal_id not in incident.absorbed_signal_ids
    assert set(incident.absorbed_signal_ids) == all_signal_ids - {rdp_signal_id}

    # 15: no same-rule dedup happened, so duplicate_signal_count is 0 - the
    # three signals were absorbed by incident correlation, not deleted.
    assert result.metrics.duplicate_signal_count == 0

    # 16: merge_count is the number of absorbed supporting signals.
    assert result.metrics.merge_count == 2
    assert result.metrics.incident_count == 1

    # Correlation metrics are bounded scalars, not mutable lists.
    assert incident.metrics["correlation_version"] == "2"
    assert incident.metrics["correlated_signal_count"] == 3
    assert incident.metrics["absorbed_signal_count"] == 2
    assert incident.metrics["primary_signal_id"] == rdp_signal_id


# ---------------------------------------------------------------------------
# 18. Context IDs bounded, deterministic, duplicate-free
# ---------------------------------------------------------------------------


def test_correlated_incident_context_is_bounded_and_duplicate_free() -> None:
    settings = _scoped_settings(MAX_CONTEXT_EVENTS_PER_INCIDENT=3)
    events = _correlated_probe_events()

    context_events = [
        build_event(
            f"ctx-{i}",
            timestamp=FIXED_TIME,
            src_ip=ENTITY,
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=3389,
            protocol="TCP",
            action="allow",
            tcp_flags="SYN",
        )
        for i in range(6)
    ]

    result = DetectionEngine(registry=_scoped_registry(), settings=settings).analyze(
        events, context_events
    )

    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert len(incident.context_event_ids) == 3
    assert len(incident.context_event_ids) == len(set(incident.context_event_ids))
    assert set(incident.context_event_ids).isdisjoint(incident.event_ids)


# ---------------------------------------------------------------------------
# 21. High-value attached sequence still routes to individual_triage
# ---------------------------------------------------------------------------


def test_high_value_attached_signal_forces_individual_triage() -> None:
    incident = _correlated_incident_bundle_stub()
    decision = decide_route(
        incident,
        [],
        [],
        frozenset({"rdp_probe", "dnat_sensitive_service_exposure"}),
        DetectionSettings(),
    )
    assert decision.route == "individual_triage"
    assert decision.llm_invoked is True


def _correlated_incident_bundle_stub():
    from agent.detection.models import IncidentBundle

    return IncidentBundle(
        incident_id="INC-STUB",
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="stub",
        severity="high",
        confidence=0.8,
        first_seen=FIXED_TIME,
        last_seen=FIXED_TIME,
        primary_entity=ENTITY,
        target_entities=[],
        signal_ids=["sig-rdp", "sig-dnat"],
        event_ids=[],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="stub",
    )


# ---------------------------------------------------------------------------
# 19 & 20. AnalysisService routes/reports once per correlated campaign
# ---------------------------------------------------------------------------


def test_analysis_service_routes_once_for_one_correlated_campaign() -> None:
    svc = AnalysisService()
    svc.detection_engine = DetectionEngine(
        registry=_scoped_registry(), settings=_scoped_settings()
    )

    result = svc.analyze_events(_correlated_probe_events(), run_triage=True)

    assert result.detection_result is not None
    assert len(result.detection_result.incidents) == 1
    # One correlated campaign -> exactly one routed/reported incident state,
    # never three duplicate individual reports.
    assert len(result.incidents) == 1
    assert result.routing_metrics["total_incidents"] == 1
    state = result.incidents[0]
    assert state.get("triage_route") in {
        "deterministic_report",
        "individual_triage",
        "digest",
        "store_only",
    }
    if state.get("triage_route") == "deterministic_report":
        assert state.get("final_report")


# ---------------------------------------------------------------------------
# 22. Fresh and idempotently hydrated correlated incidents are equivalent
# ---------------------------------------------------------------------------


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def test_fresh_and_hydrated_correlated_incident_are_equivalent(session_factory) -> None:
    svc = AnalysisService()
    svc.detection_engine = DetectionEngine(
        registry=_scoped_registry(), settings=_scoped_settings()
    )
    fresh_result = svc.analyze_events(_correlated_probe_events(), run_triage=True)
    assert len(fresh_result.incidents) == 1
    fresh_state = fresh_result.incidents[0]
    fresh_incident = fresh_result.detection_result.incidents[0]

    with session_factory() as session:
        session.add(
            IngestionJob(
                id="job-corr-1",
                idempotency_key="idem-corr-1",
                source_name="test",
                status="processing",
            )
        )
        session.commit()

    fresh_result.job_id = "job-corr-1"
    persist_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    persist_svc._persist_analysis(fresh_result, run_triage=True)

    hydrate_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    hydrated_result = hydrate_svc.analyze_file(
        "nonexistent-file-not-touched.jsonl",
        run_triage=True,
        idempotency_key="idem-corr-1",
    )

    assert hydrated_result.reused is True
    assert len(hydrated_result.incidents) == 1
    hydrated_state = hydrated_result.incidents[0]
    hydrated_incident = hydrated_result.detection_result.incidents[0]

    assert hydrated_incident.incident_id == fresh_incident.incident_id
    assert hydrated_incident.incident_type == fresh_incident.incident_type
    assert hydrated_incident.incident_family == fresh_incident.incident_family
    assert hydrated_incident.primary_entity == fresh_incident.primary_entity
    assert set(hydrated_incident.signal_ids) == set(fresh_incident.signal_ids)
    assert set(hydrated_incident.absorbed_signal_ids) == set(
        fresh_incident.absorbed_signal_ids
    )
    assert set(hydrated_incident.event_ids) == set(fresh_incident.event_ids)
    assert hydrated_incident.severity == fresh_incident.severity
    assert hydrated_incident.confidence == pytest.approx(fresh_incident.confidence)
    assert hydrated_incident.merge_key == fresh_incident.merge_key
    assert hydrated_incident.merge_key != ""
    assert hydrated_state.get("triage_route") == fresh_state.get("triage_route")
    assert hydrated_result.routing_metrics["provider_invocation_count"] == (
        fresh_result.routing_metrics["provider_invocation_count"]
    )


# ---------------------------------------------------------------------------
# 23 & 24. Backward compatibility guardrails
# ---------------------------------------------------------------------------


def test_default_registry_still_has_exactly_36_rules() -> None:
    register_default_rules()
    rules = default_registry.get_all_rules()
    assert len(rules) == 36
    assert len({rule.rule_id for rule in rules}) == 36


def test_settings_reject_invalid_correlation_values() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DetectionSettings.model_validate({"INCIDENT_MERGE_WINDOW_SECONDS": 0})
    with pytest.raises(ValidationError):
        DetectionSettings.model_validate({"INCIDENT_EVENT_OVERLAP_THRESHOLD": 1.5})
    with pytest.raises(ValidationError):
        DetectionSettings.model_validate({"INCIDENT_EVENT_OVERLAP_THRESHOLD": -0.1})
    with pytest.raises(ValidationError):
        DetectionSettings.model_validate({"MAX_CONTEXT_EVENTS_PER_INCIDENT": 0})


# ---------------------------------------------------------------------------
# Merge-blocker fix 1: narrow cross-primary correlation for real exposure
# rules that view the same firewall event from different entity angles.
# ---------------------------------------------------------------------------


def _exposure_settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "INBOUND_EXPOSURE_WINDOW_SECONDS": 300,
        "CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS": 1,
        # Only one sanitized PF event is used for this scenario.
        "WAN_TO_LAN_MIN_ALLOWED_EVENTS": 1,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def test_real_exposure_rules_correlate_across_different_primary_entities() -> None:
    # One sanitized PF event: an external source reaches a DNAT'd, WAN->LAN
    # allowed connection to Redis (a critical management port), sufficient
    # to independently qualify for all three exposure/policy rules, each of
    # which uses a different entity as its own primary_entity.
    event = build_event(
        "exposure-1",
        timestamp=FIXED_TIME,
        src_ip="8.8.8.8",
        dst_ip="203.0.113.50",
        dst_port=6379,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN,ACK",
        inbound_zone="wan",
        outbound_zone="lan",
        translated_dst_ip="10.0.0.60",
        nat_type="dnat",
        parser_name="pf_firewall",
    )

    registry = RuleRegistry()
    registry.register(CriticalManagementServiceExposedRule())
    registry.register(DnatSensitiveServiceExposureRule())
    registry.register(WanToLanSensitiveServiceAllowedRule())

    result = DetectionEngine(registry=registry, settings=_exposure_settings()).analyze(
        [event]
    )

    assert {signal.rule_id for signal in result.signals} == {
        "critical_management_service_exposed",
        "dnat_sensitive_service_exposure",
        "wan_to_lan_sensitive_service_allowed",
    }
    # The real rule outputs use different primary_entity values (external
    # source for critical, effective internal destination for the other
    # two) - confirming this is not a manually-crafted same-entity fixture.
    primary_entities = {signal.primary_entity for signal in result.signals}
    assert len(primary_entities) == 2
    assert "8.8.8.8" in primary_entities
    assert "10.0.0.60" in primary_entities

    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.incident_type == "critical_management_service_exposed"
    assert set(incident.signal_ids) == {s.signal_id for s in result.signals}
    assert incident.primary_entity == "8.8.8.8"


def test_exposure_signals_with_disjoint_events_do_not_cross_primary_correlate() -> None:
    # Two independent DNAT exposures to different internal destinations.
    # Same family, same window, but no shared event evidence at all - the
    # narrow cross-primary exception must not fire.
    event_a = build_event(
        "exposure-a",
        timestamp=FIXED_TIME,
        src_ip="8.8.8.8",
        dst_ip="203.0.113.50",
        dst_port=6379,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN,ACK",
        inbound_zone="wan",
        outbound_zone="lan",
        translated_dst_ip="10.0.0.60",
        nat_type="dnat",
        parser_name="pf_firewall",
    )
    event_b = build_event(
        "exposure-b",
        timestamp=FIXED_TIME,
        src_ip="9.9.9.9",
        dst_ip="203.0.113.51",
        dst_port=6379,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN,ACK",
        inbound_zone="wan",
        outbound_zone="lan",
        translated_dst_ip="10.0.0.61",
        nat_type="dnat",
        parser_name="pf_firewall",
    )

    registry = RuleRegistry()
    registry.register(CriticalManagementServiceExposedRule())
    registry.register(DnatSensitiveServiceExposureRule())

    result = DetectionEngine(registry=registry, settings=_exposure_settings()).analyze(
        [event_a, event_b]
    )

    assert len(result.signals) == 4
    assert len(result.incidents) == 2


# ---------------------------------------------------------------------------
# Merge-blocker fix 2: real shared-event evidence required even at
# overlap_threshold 0.0.
# ---------------------------------------------------------------------------


def test_threshold_zero_disjoint_event_sets_stay_separate() -> None:
    a = _signal(
        "sig-a", "rdp_probe", "rdp_probe", "service_probing", ["e1", "e2"]
    )
    b = _signal(
        "sig-b",
        "network_scan_horizontal",
        "horizontal_scan",
        "network_scanning",
        ["e3", "e4"],
    )
    clusters = cluster_signals([a, b], window_seconds=300, overlap_threshold=0.0)
    assert len(clusters) == 2


def test_threshold_zero_empty_event_set_stays_separate() -> None:
    a = _signal("sig-a", "rdp_probe", "rdp_probe", "service_probing", [])
    b = _signal(
        "sig-b",
        "network_scan_horizontal",
        "horizontal_scan",
        "network_scanning",
        ["e1", "e2"],
    )
    clusters = cluster_signals([a, b], window_seconds=300, overlap_threshold=0.0)
    assert len(clusters) == 2


def test_threshold_zero_one_shared_event_may_correlate() -> None:
    a = _signal(
        "sig-a", "rdp_probe", "rdp_probe", "service_probing", ["e1", "e2", "e3"]
    )
    b = _signal(
        "sig-b",
        "network_scan_horizontal",
        "horizontal_scan",
        "network_scanning",
        ["e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10"],
    )
    assert event_overlap_ratio(a, b) == pytest.approx(1 / 3)

    clusters = cluster_signals([a, b], window_seconds=300, overlap_threshold=0.0)

    assert len(clusters) == 1
    assert {s.signal_id for s in clusters[0]} == {"sig-a", "sig-b"}
