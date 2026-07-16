from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent.application.retention import RetentionPolicy
from agent.config import Settings


RETENTION_ENVIRONMENT_KEYS = (
    "RETENTION_POLICY_VERSION",
    "RETENTION_CANONICAL_EVENT_DAYS",
    "RETENTION_DETECTION_SIGNAL_DAYS",
    "RETENTION_COMPLETED_JOB_DAYS",
    "RETENTION_TERMINAL_INCIDENT_DAYS",
    "RETENTION_AUDIT_EVENT_DAYS",
)


def _clean_retention_environment(monkeypatch) -> None:
    for key in RETENTION_ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_policy_defaults(monkeypatch) -> None:
    _clean_retention_environment(monkeypatch)
    policy = RetentionPolicy.from_settings(Settings(_env_file=None))
    assert policy == RetentionPolicy(
        version="v1",
        canonical_event_days=30,
        detection_signal_days=90,
        completed_job_days=90,
        terminal_incident_days=365,
        audit_event_days=365,
    )


def test_policy_environment_overrides(monkeypatch) -> None:
    _clean_retention_environment(monkeypatch)
    monkeypatch.setenv("RETENTION_POLICY_VERSION", "v2.1")
    monkeypatch.setenv("RETENTION_CANONICAL_EVENT_DAYS", "31")
    monkeypatch.setenv("RETENTION_DETECTION_SIGNAL_DAYS", "91")
    monkeypatch.setenv("RETENTION_COMPLETED_JOB_DAYS", "92")
    monkeypatch.setenv("RETENTION_TERMINAL_INCIDENT_DAYS", "366")
    monkeypatch.setenv("RETENTION_AUDIT_EVENT_DAYS", "367")
    policy = RetentionPolicy.from_settings(Settings(_env_file=None))
    assert policy == RetentionPolicy("v2.1", 31, 91, 92, 366, 367)


@pytest.mark.parametrize("value", [0, -1])
def test_policy_rejects_non_positive_days(value) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, retention_canonical_event_days=value)

    with pytest.raises(ValueError, match="retention_policy_days_invalid"):
        RetentionPolicy("v1", value, 90, 90, 365, 365)


@pytest.mark.parametrize("version", ["", "contains spaces", "*invalid"])
def test_policy_rejects_invalid_version(version) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, retention_policy_version=version)
