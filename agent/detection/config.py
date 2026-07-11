import os
from pydantic import BaseModel
from typing import List

class DetectionSettings(BaseModel):
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

    # Remote Service Probe (RDP/SSH)
    REMOTE_SERVICE_WINDOW_SECONDS: int = int(os.getenv("REMOTE_SERVICE_WINDOW_SECONDS", "300"))
    RDP_PORTS: List[int] = [3389]
    SSH_PORTS: List[int] = [22]
    REMOTE_SERVICE_MIN_EVENTS: int = int(os.getenv("REMOTE_SERVICE_MIN_EVENTS", "5"))
    REMOTE_SERVICE_MIN_DISTINCT_TARGETS: int = int(os.getenv("REMOTE_SERVICE_MIN_DISTINCT_TARGETS", "3"))
    REMOTE_SERVICE_MIN_BLOCK_RATIO: float = float(os.getenv("REMOTE_SERVICE_MIN_BLOCK_RATIO", "0.60"))

    # SPI Anomaly
    SPI_ANOMALY_WINDOW_SECONDS: int = int(os.getenv("SPI_ANOMALY_WINDOW_SECONDS", "300"))
    SPI_ANOMALY_MIN_EVENTS: int = int(os.getenv("SPI_ANOMALY_MIN_EVENTS", "5"))
    SPI_ANOMALY_MIN_DISTINCT_TARGETS: int = int(os.getenv("SPI_ANOMALY_MIN_DISTINCT_TARGETS", "2"))

    # Network Flood
    NETWORK_FLOOD_WINDOW_SECONDS: int = int(os.getenv("NETWORK_FLOOD_WINDOW_SECONDS", "60"))
    NETWORK_FLOOD_MIN_EVENTS: int = int(os.getenv("NETWORK_FLOOD_MIN_EVENTS", "100"))
    NETWORK_FLOOD_MIN_BLOCK_RATIO: float = float(os.getenv("NETWORK_FLOOD_MIN_BLOCK_RATIO", "0.80"))

    # Incident Merging
    INCIDENT_MERGE_WINDOW_SECONDS: int = int(os.getenv("INCIDENT_MERGE_WINDOW_SECONDS", "300"))
    INCIDENT_EVENT_OVERLAP_THRESHOLD: float = float(os.getenv("INCIDENT_EVENT_OVERLAP_THRESHOLD", "0.70"))
    MAX_CONTEXT_EVENTS_PER_INCIDENT: int = int(os.getenv("MAX_CONTEXT_EVENTS_PER_INCIDENT", "50"))

settings = DetectionSettings()
