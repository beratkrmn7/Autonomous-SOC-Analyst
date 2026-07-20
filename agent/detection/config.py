import json
import os
from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _integer_tuple_from_env(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    value = raw_value.strip()
    if not value:
        return default
    if value.startswith("["):
        parsed = json.loads(value)
        if not isinstance(parsed, list):
            raise ValueError(f"{name} must be a JSON array or comma-separated integers")
        return tuple(int(item) for item in parsed)
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())

class DetectionSettings(BaseModel):
    model_config = ConfigDict(validate_default=True)

    # Global Settings
    DETECTION_MAX_LATENESS_SECONDS: int = int(os.getenv("DETECTION_MAX_LATENESS_SECONDS", "120"))
    INTERNAL_NETWORKS: List[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    # Horizontal Scan
    HORIZONTAL_SCAN_WINDOW_SECONDS: int = int(os.getenv("HORIZONTAL_SCAN_WINDOW_SECONDS", "300"))
    HORIZONTAL_SCAN_MIN_EVENTS: int = int(os.getenv("HORIZONTAL_SCAN_MIN_EVENTS", "10"))
    HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS: int = int(os.getenv("HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS", "8"))
    HORIZONTAL_SCAN_MIN_BLOCK_RATIO: float = float(os.getenv("HORIZONTAL_SCAN_MIN_BLOCK_RATIO", "0.60"))
    HORIZONTAL_SCAN_MIN_SYN_RATIO: float = float(os.getenv("HORIZONTAL_SCAN_MIN_SYN_RATIO", "0.50"))

    # Vertical Scan
    VERTICAL_SCAN_WINDOW_SECONDS: int = int(os.getenv("VERTICAL_SCAN_WINDOW_SECONDS", "300"))
    VERTICAL_SCAN_MIN_EVENTS: int = int(os.getenv("VERTICAL_SCAN_MIN_EVENTS", "10"))
    VERTICAL_SCAN_MIN_DISTINCT_PORTS: int = int(os.getenv("VERTICAL_SCAN_MIN_DISTINCT_PORTS", "8"))
    VERTICAL_SCAN_MIN_BLOCK_RATIO: float = float(os.getenv("VERTICAL_SCAN_MIN_BLOCK_RATIO", "0.60"))
    VERTICAL_SCAN_MIN_SYN_RATIO: float = float(os.getenv("VERTICAL_SCAN_MIN_SYN_RATIO", "0.50"))

    # Remote Service Probe (RDP/SSH)
    REMOTE_SERVICE_WINDOW_SECONDS: int = int(os.getenv("REMOTE_SERVICE_WINDOW_SECONDS", "300"))
    RDP_PORTS: List[int] = [3389]
    SSH_PORTS: List[int] = [22]
    REMOTE_SERVICE_MIN_EVENTS: int = int(os.getenv("REMOTE_SERVICE_MIN_EVENTS", "5"))
    REMOTE_SERVICE_MIN_DISTINCT_TARGETS: int = int(os.getenv("REMOTE_SERVICE_MIN_DISTINCT_TARGETS", "3"))
    REMOTE_SERVICE_MIN_BLOCK_RATIO: float = float(os.getenv("REMOTE_SERVICE_MIN_BLOCK_RATIO", "0.60"))
    REMOTE_SERVICE_MIN_SYN_RATIO: float = float(os.getenv("REMOTE_SERVICE_MIN_SYN_RATIO", "0.50"))

    # Extended Remote Service Probe Pack
    EXTENDED_SERVICE_PROBE_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("EXTENDED_SERVICE_PROBE_WINDOW_SECONDS", "300")), gt=0
    )
    EXTENDED_SERVICE_PROBE_MIN_EVENTS: int = Field(
        default=int(os.getenv("EXTENDED_SERVICE_PROBE_MIN_EVENTS", "5")), gt=0
    )
    EXTENDED_SERVICE_PROBE_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("EXTENDED_SERVICE_PROBE_MIN_DISTINCT_TARGETS", "3")),
        gt=0,
    )
    EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    EXTENDED_SERVICE_PROBE_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("EXTENDED_SERVICE_PROBE_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )
    WEB_ADMIN_PROBE_MIN_EVENTS: int = Field(
        default=int(os.getenv("WEB_ADMIN_PROBE_MIN_EVENTS", "8")), gt=0
    )
    WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS", "5")),
        gt=0,
    )
    WEB_ADMIN_PROBE_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("WEB_ADMIN_PROBE_MIN_BLOCK_RATIO", "0.80")),
        ge=0.0,
        le=1.0,
    )
    WEB_ADMIN_PROBE_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("WEB_ADMIN_PROBE_MIN_SYN_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )

    # TCP Flag Scan and Invalid Combination Anomalies
    TCP_FLAG_SCAN_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("TCP_FLAG_SCAN_WINDOW_SECONDS", "300")), gt=0
    )
    TCP_FLAG_SCAN_MIN_EVENTS: int = Field(
        default=int(os.getenv("TCP_FLAG_SCAN_MIN_EVENTS", "5")), gt=0
    )
    TCP_FLAG_SCAN_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("TCP_FLAG_SCAN_MIN_DISTINCT_TARGETS", "3")), gt=0
    )
    TCP_FLAG_SCAN_MIN_DISTINCT_PORTS: int = Field(
        default=int(os.getenv("TCP_FLAG_SCAN_MIN_DISTINCT_PORTS", "3")), gt=0
    )
    TCP_FLAG_SCAN_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("TCP_FLAG_SCAN_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    TCP_ACK_SCAN_MIN_EVENTS: int = Field(
        default=int(os.getenv("TCP_ACK_SCAN_MIN_EVENTS", "10")), gt=0
    )
    TCP_ACK_SCAN_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("TCP_ACK_SCAN_MIN_BLOCK_RATIO", "0.85")),
        ge=0.0,
        le=1.0,
    )
    TCP_INVALID_COMBINATION_MIN_EVENTS: int = Field(
        default=int(os.getenv("TCP_INVALID_COMBINATION_MIN_EVENTS", "5")), gt=0
    )
    TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO: float = Field(
        default=float(
            os.getenv("TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO", "0.80")
        ),
        ge=0.0,
        le=1.0,
    )

    # Repeated TCP Reset Anomaly
    TCP_RESET_ANOMALY_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("TCP_RESET_ANOMALY_WINDOW_SECONDS", "300")), gt=0
    )
    TCP_RESET_ANOMALY_MIN_EVENTS: int = Field(
        default=int(os.getenv("TCP_RESET_ANOMALY_MIN_EVENTS", "10")), gt=0
    )
    TCP_RESET_ANOMALY_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("TCP_RESET_ANOMALY_MIN_DISTINCT_TARGETS", "3")),
        gt=0,
    )
    TCP_RESET_ANOMALY_MIN_DISTINCT_PORTS: int = Field(
        default=int(os.getenv("TCP_RESET_ANOMALY_MIN_DISTINCT_PORTS", "3")),
        gt=0,
    )
    TCP_RESET_ANOMALY_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("TCP_RESET_ANOMALY_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )

    # Explicit SPI Blocks Followed by an Allowed Connection
    SPI_THEN_ALLOWED_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("SPI_THEN_ALLOWED_WINDOW_SECONDS", "600")), gt=0
    )
    SPI_THEN_ALLOWED_MIN_SPI_EVENTS: int = Field(
        default=int(os.getenv("SPI_THEN_ALLOWED_MIN_SPI_EVENTS", "3")), gt=0
    )

    # SPI Anomaly
    SPI_ANOMALY_WINDOW_SECONDS: int = int(os.getenv("SPI_ANOMALY_WINDOW_SECONDS", "300"))
    SPI_ANOMALY_MIN_EVENTS: int = int(os.getenv("SPI_ANOMALY_MIN_EVENTS", "5"))
    SPI_ANOMALY_MIN_DISTINCT_TARGETS: int = int(os.getenv("SPI_ANOMALY_MIN_DISTINCT_TARGETS", "1"))
    SPI_ANOMALY_FALLBACK_RAW_MATCH: bool = os.getenv("SPI_ANOMALY_FALLBACK_RAW_MATCH", "true").lower() == "true"

    # Network Flood
    NETWORK_FLOOD_WINDOW_SECONDS: int = int(os.getenv("NETWORK_FLOOD_WINDOW_SECONDS", "60"))
    NETWORK_FLOOD_MIN_EVENTS: int = int(os.getenv("NETWORK_FLOOD_MIN_EVENTS", "100"))
    NETWORK_FLOOD_MIN_BLOCK_RATIO: float = float(os.getenv("NETWORK_FLOOD_MIN_BLOCK_RATIO", "0.80"))

    # Low-and-slow Horizontal Scan
    LOW_SLOW_HORIZONTAL_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("LOW_SLOW_HORIZONTAL_WINDOW_SECONDS", "3600")), gt=0
    )
    LOW_SLOW_HORIZONTAL_MIN_EVENTS: int = Field(
        default=int(os.getenv("LOW_SLOW_HORIZONTAL_MIN_EVENTS", "12")), gt=0
    )
    LOW_SLOW_HORIZONTAL_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("LOW_SLOW_HORIZONTAL_MIN_DISTINCT_TARGETS", "8")), gt=0
    )
    LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS: int = Field(
        default=int(os.getenv("LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS", "900")), gt=0
    )
    LOW_SLOW_HORIZONTAL_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("LOW_SLOW_HORIZONTAL_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    LOW_SLOW_HORIZONTAL_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("LOW_SLOW_HORIZONTAL_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )

    # Low-and-slow Vertical Scan
    LOW_SLOW_VERTICAL_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("LOW_SLOW_VERTICAL_WINDOW_SECONDS", "3600")), gt=0
    )
    LOW_SLOW_VERTICAL_MIN_EVENTS: int = Field(
        default=int(os.getenv("LOW_SLOW_VERTICAL_MIN_EVENTS", "12")), gt=0
    )
    LOW_SLOW_VERTICAL_MIN_DISTINCT_PORTS: int = Field(
        default=int(os.getenv("LOW_SLOW_VERTICAL_MIN_DISTINCT_PORTS", "8")), gt=0
    )
    LOW_SLOW_VERTICAL_MIN_SPAN_SECONDS: int = Field(
        default=int(os.getenv("LOW_SLOW_VERTICAL_MIN_SPAN_SECONDS", "900")), gt=0
    )
    LOW_SLOW_VERTICAL_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("LOW_SLOW_VERTICAL_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    LOW_SLOW_VERTICAL_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("LOW_SLOW_VERTICAL_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )

    # Repeated Blocked Scanner
    REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS", "300")), gt=0
    )
    REPEATED_BLOCKED_SCANNER_MIN_EVENTS: int = Field(
        default=int(os.getenv("REPEATED_BLOCKED_SCANNER_MIN_EVENTS", "6")), gt=0
    )
    REPEATED_BLOCKED_SCANNER_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("REPEATED_BLOCKED_SCANNER_MIN_BLOCK_RATIO", "0.80")),
        ge=0.0,
        le=1.0,
    )
    REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS: int = Field(
        default=int(
            os.getenv("REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS", "2")
        ),
        gt=0,
    )
    REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS: int = Field(
        default=int(os.getenv("REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS", "2")),
        gt=0,
    )

    # Internal Lateral Scan
    INTERNAL_LATERAL_SCAN_PORTS: tuple[int, ...] = Field(
        default=_integer_tuple_from_env(
            "INTERNAL_LATERAL_SCAN_PORTS",
            (22, 135, 139, 445, 3389, 5900, 5985, 5986),
        ),
        min_length=1,
    )
    INTERNAL_LATERAL_SCAN_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("INTERNAL_LATERAL_SCAN_WINDOW_SECONDS", "300")), gt=0
    )
    INTERNAL_LATERAL_SCAN_MIN_EVENTS: int = Field(
        default=int(os.getenv("INTERNAL_LATERAL_SCAN_MIN_EVENTS", "5")), gt=0
    )
    INTERNAL_LATERAL_SCAN_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("INTERNAL_LATERAL_SCAN_MIN_DISTINCT_TARGETS", "3")),
        gt=0,
    )
    INTERNAL_LATERAL_SCAN_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("INTERNAL_LATERAL_SCAN_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    INTERNAL_LATERAL_SCAN_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("INTERNAL_LATERAL_SCAN_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )

    # Subnet Sweep
    SUBNET_SWEEP_IPV4_PREFIX: int = Field(
        default=int(os.getenv("SUBNET_SWEEP_IPV4_PREFIX", "24")), ge=0, le=32
    )
    SUBNET_SWEEP_IPV6_PREFIX: int = Field(
        default=int(os.getenv("SUBNET_SWEEP_IPV6_PREFIX", "64")), ge=0, le=128
    )
    SUBNET_SWEEP_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("SUBNET_SWEEP_WINDOW_SECONDS", "300")), gt=0
    )
    SUBNET_SWEEP_MIN_EVENTS: int = Field(
        default=int(os.getenv("SUBNET_SWEEP_MIN_EVENTS", "8")), gt=0
    )
    SUBNET_SWEEP_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("SUBNET_SWEEP_MIN_DISTINCT_TARGETS", "6")), gt=0
    )
    SUBNET_SWEEP_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("SUBNET_SWEEP_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    SUBNET_SWEEP_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("SUBNET_SWEEP_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )

    # Distributed Scan
    DISTRIBUTED_SCAN_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("DISTRIBUTED_SCAN_WINDOW_SECONDS", "300")), gt=0
    )
    DISTRIBUTED_SCAN_MIN_EVENTS: int = Field(
        default=int(os.getenv("DISTRIBUTED_SCAN_MIN_EVENTS", "12")), gt=0
    )
    DISTRIBUTED_SCAN_MIN_DISTINCT_SOURCES: int = Field(
        default=int(os.getenv("DISTRIBUTED_SCAN_MIN_DISTINCT_SOURCES", "6")), gt=0
    )
    DISTRIBUTED_SCAN_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("DISTRIBUTED_SCAN_MIN_BLOCK_RATIO", "0.80")),
        ge=0.0,
        le=1.0,
    )
    DISTRIBUTED_SCAN_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("DISTRIBUTED_SCAN_MIN_SYN_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )

    # Multi-service Sweep
    MULTI_SERVICE_SWEEP_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("MULTI_SERVICE_SWEEP_WINDOW_SECONDS", "300")), gt=0
    )
    MULTI_SERVICE_SWEEP_MIN_EVENTS: int = Field(
        default=int(os.getenv("MULTI_SERVICE_SWEEP_MIN_EVENTS", "8")), gt=0
    )
    MULTI_SERVICE_SWEEP_MIN_DISTINCT_SERVICES: int = Field(
        default=int(os.getenv("MULTI_SERVICE_SWEEP_MIN_DISTINCT_SERVICES", "3")),
        gt=0,
    )
    MULTI_SERVICE_SWEEP_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("MULTI_SERVICE_SWEEP_MIN_DISTINCT_TARGETS", "3")),
        gt=0,
    )
    MULTI_SERVICE_SWEEP_MIN_BLOCK_RATIO: float = Field(
        default=float(os.getenv("MULTI_SERVICE_SWEEP_MIN_BLOCK_RATIO", "0.60")),
        ge=0.0,
        le=1.0,
    )
    MULTI_SERVICE_SWEEP_MIN_SYN_RATIO: float = Field(
        default=float(os.getenv("MULTI_SERVICE_SWEEP_MIN_SYN_RATIO", "0.50")),
        ge=0.0,
        le=1.0,
    )

    # Scan followed by an Allowed Connection
    SCAN_THEN_ALLOWED_WINDOW_SECONDS: int = Field(
        default=int(os.getenv("SCAN_THEN_ALLOWED_WINDOW_SECONDS", "600")), gt=0
    )
    SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS: int = Field(
        default=int(os.getenv("SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS", "5")), gt=0
    )
    SCAN_THEN_ALLOWED_MIN_DISTINCT_TARGETS: int = Field(
        default=int(os.getenv("SCAN_THEN_ALLOWED_MIN_DISTINCT_TARGETS", "2")), gt=0
    )
    SCAN_THEN_ALLOWED_MIN_DISTINCT_PORTS: int = Field(
        default=int(os.getenv("SCAN_THEN_ALLOWED_MIN_DISTINCT_PORTS", "2")), gt=0
    )

    # Incident Merging
    INCIDENT_MERGE_WINDOW_SECONDS: int = int(os.getenv("INCIDENT_MERGE_WINDOW_SECONDS", "300"))
    INCIDENT_EVENT_OVERLAP_THRESHOLD: float = float(os.getenv("INCIDENT_EVENT_OVERLAP_THRESHOLD", "0.70"))
    MAX_CONTEXT_EVENTS_PER_INCIDENT: int = int(os.getenv("MAX_CONTEXT_EVENTS_PER_INCIDENT", "50"))

    @field_validator("INTERNAL_LATERAL_SCAN_PORTS")
    @classmethod
    def validate_internal_lateral_scan_ports(
        cls, value: tuple[int, ...]
    ) -> tuple[int, ...]:
        if any(port < 1 or port > 65_535 for port in value):
            raise ValueError("INTERNAL_LATERAL_SCAN_PORTS must contain valid TCP ports")
        if len(value) != len(set(value)):
            raise ValueError("INTERNAL_LATERAL_SCAN_PORTS must be duplicate-free")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_low_and_slow_spans(self) -> "DetectionSettings":
        if (
            self.LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS
            > self.LOW_SLOW_HORIZONTAL_WINDOW_SECONDS
        ):
            raise ValueError(
                "LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS must not exceed its window"
            )
        if (
            self.LOW_SLOW_VERTICAL_MIN_SPAN_SECONDS
            > self.LOW_SLOW_VERTICAL_WINDOW_SECONDS
        ):
            raise ValueError(
                "LOW_SLOW_VERTICAL_MIN_SPAN_SECONDS must not exceed its window"
            )
        return self

settings = DetectionSettings()
