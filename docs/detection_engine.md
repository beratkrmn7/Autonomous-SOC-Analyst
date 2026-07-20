# Phase 3 Detection and Correlation Engine

The Phase 3 Detection and Correlation engine replaces heuristic scripts with a deterministic, testable, robust, and extensible rules engine focused on generating low-false-positive `IncidentBundle` objects.

## Architecture

Data flows through the following stages:

1. **Role Classification**: `EventFilter` classifies parsed events as candidate, context, or probable noise for reporting and context selection. This role does not define detection eligibility.
2. **Eligibility Check**: All successfully parsed and semantically valid events are available to deterministic rules. `DetectionEngine` rejects invalid statuses, missing timestamps, and other ineligible inputs before rule execution.
3. **Rule Evaluation**: A `RuleRegistry` loads all implementations of `BaseDetectionRule`. Each rule owns its relevance decisions, evaluates the eligible log sequence using `sliding_window_scan`, and generates `DetectionSignal` objects.
4. **Signal Deduplication**: Redundant, identical signals across multiple windows are pruned.
5. **Signal Suppression**: Allows IP whitelisting to silently discard acceptable traffic (e.g. Vuln Scanners).
6. **Correlation & Incident Merging**: `DetectionSignal` objects related to the same primary entity or matching keys are merged into `IncidentBundle` objects. Role-classified context remains a bounded, same-source, nearby-time subset and cannot duplicate incident event IDs.

## Adding a Detection Rule

Extend `BaseDetectionRule` and declare one immutable `DetectionRuleMetadata` instance. Metadata is the single source of truth for the legacy `rule_id`, `version`, `name`, `family`, and `priority` attributes. Identifiers use lowercase snake case, versions use numeric `major.minor.patch` format, canonical field names must exist on `CanonicalLogEvent`, and threshold references must name real `DetectionSettings` fields.

```python
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors.base import BaseDetectionRule

class ExampleRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="example_rule",
        version="1.0.0",
        name="Example Rule",
        family="example_family",
        priority=500,
        supported_event_types=(),
        required_fields=("src_ip",),
        signal_type="example_signal",
        default_severity="low",
        mitre_techniques=(),
        window_setting=None,
        minimum_events_setting=None,
    )

    def evaluate(self, events, context):
        return []
```

`required_fields` is a rule-level relevance filter: `None` and blank strings are missing, while numeric zero and `False` remain valid. An empty tuple adds no field requirement. `supported_event_types` restricts only explicitly declared values; an empty tuple accepts all globally eligible events, including events without `event_type`. It never infers a type from parser or message content.

Registration validates the complete contract. Re-registering the same class, version, and metadata is an idempotent no-op; the same `rule_id` with another class, version, or incompatible metadata is rejected. Rules are always evaluated by ascending `(priority, rule_id)`.

Every emitted signal must match the producing rule's identity, version, name, family, and `signal_type`. A rule that intentionally preserves multiple legacy signal identities may declare an immutable `signal_variants` tuple; each emitted `(rule_id, rule_name, signal_type)` must then exactly match one declared variant, while version and family still match the parent rule metadata. Signals must also have a non-empty primary entity and event set, reference only events supplied to that rule, and keep every evidence event inside the signal event set. Invalid signals are excluded with a bounded warning, while other rules continue. Generate signal IDs from stable inputs with `generate_signal_id`; never use current time or unordered runtime data.

Rule tests should include positive, negative, and threshold-boundary cases, deterministic repeated evaluation, evidence ownership, and duplicate-signal checks. Detection and ingestion rules must remain completely local and make zero provider or agent calls.

The system includes pre-built rules for:
- Horizontal Scan
- Vertical Scan
- Remote Service Probe (SSH/RDP)
- Network Flood (DoS)
- SPI Anomaly Burst

## Phase 6B.1 Advanced Scan Pack

The advanced scan pack is deliberately batch-local: every correlation below uses only
events supplied to the current `DetectionEngine.analyze()` call. It does not retain
cross-file or cross-job state and does not query databases, Redis, OpenSearch, providers,
or LLMs.

| Rule ID | Signal type | Family | Primary grouping | Window setting | Scope |
| --- | --- | --- | --- | --- | --- |
| `low_and_slow_horizontal_scan` | `low_and_slow_horizontal_scan` | `network_scanning` | source, destination port, protocol | `LOW_SLOW_HORIZONTAL_WINDOW_SECONDS` | Batch-local |
| `low_and_slow_vertical_scan` | `low_and_slow_vertical_scan` | `network_scanning` | source, destination, protocol | `LOW_SLOW_VERTICAL_WINDOW_SECONDS` | Batch-local |
| `repeated_blocked_scanner` | `repeated_blocked_scanner` | `network_scanning` | source | `REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS` | Batch-local |
| `internal_lateral_scan` | `internal_lateral_scan` | `lateral_movement_candidate` | private source across private targets | `INTERNAL_LATERAL_SCAN_WINDOW_SECONDS` | Batch-local |
| `subnet_sweep` | `subnet_sweep` | `network_scanning` | source, destination subnet, port, protocol | `SUBNET_SWEEP_WINDOW_SECONDS` | Batch-local |
| `distributed_scan` | `distributed_scan` | `network_scanning` | destination, port, protocol | `DISTRIBUTED_SCAN_WINDOW_SECONDS` | Batch-local |
| `multi_service_sweep` | `multi_service_sweep` | `service_probing` | source across service categories | `MULTI_SERVICE_SWEEP_WINDOW_SECONDS` | Batch-local |
| `scan_followed_by_allowed_connection` | `scan_followed_by_allowed_connection` | `network_intrusion_candidate` | source plus related target/service sequence | `SCAN_THEN_ALLOWED_WINDOW_SECONDS` | Batch-local |

## Phase 6B.2 Remote Service Probe Pack

The registered rules below correlate repeated blocked TCP SYN attempts from one source
against multiple targets for one service profile. They use only the current
`DetectionEngine.analyze()` batch. Network probing is not proof of successful
authentication, exploitation, compromise, or remote execution.

| Registered rule ID | Emitted signal identities | Ports | Family | Severity | Grouping | Thresholds | Scope |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `smb_probe` | `smb_probe` | 139, 445 | `service_probing` | high | source + SMB profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `vnc_probe` | `vnc_probe` | 5900–5905 | `service_probing` | high | source + VNC profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `winrm_probe` | `winrm_probe` | 5985, 5986 | `service_probing` | high | source + WinRM profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `database_service_probe` | `mssql_probe`, `oracle_probe`, `mysql_probe`, `postgresql_probe`, `redis_probe`, `elasticsearch_probe`, `mongodb_probe` | 1433, 1521, 3306, 5432, 6379, 9200, 27017 | `service_probing` | high | source + database profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `kubernetes_service_probe` | `kubernetes_api_probe`, `kubelet_probe` | 6443, 10250 | `service_probing` | high | source + Kubernetes profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `docker_daemon_probe` | `docker_daemon_probe` | 2375, 2376 | `service_probing` | high | source + Docker profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |
| `web_admin_panel_probe` | `web_admin_panel_probe` | 8000, 8080, 8443, 8888, 9000, 9443, 10000 | `service_probing` | medium | source + web-admin profile | common window + `WEB_ADMIN_PROBE_*` | Batch-local |
| `legacy_cleartext_service_probe` | `telnet_probe`, `ftp_probe` | 23; 20, 21 | `service_probing` | medium | source + cleartext-service profile | `EXTENDED_SERVICE_PROBE_*` | Batch-local |

## Phase 6C TCP and SPI Anomaly Pack

TCP flags are normalized before detection by a vendor-neutral utility. Compact PF
characters and verbose tokens produce one deterministic representation in this order:
`FIN,SYN,RST,PSH,ACK,URG,ECE,CWR`.

| Input | Canonical value |
| --- | --- |
| `S` | `SYN` |
| `SA` | `SYN,ACK` |
| `SR` | `SYN,RST` |
| `AR` | `RST,ACK` |
| `AFR` or `RFA` | `FIN,RST,ACK` |
| `AFP` | `FIN,PSH,ACK` |
| `FPU`, `FIN PSH URG`, or `FIN|PSH|URG` | `FIN,PSH,URG` |

A missing flag field remains `None` and is not evidence of a NULL scan. An explicitly
present empty value (`""`, `0`, `NONE`, `NULL`, or `-`) becomes `NONE`. Unknown or
partially invalid values, including `.`, are not guessed and cannot match a flag rule.
PF parser metadata records only bounded original flags, deterministic tokens, field
presence, and explicit-none state.

| Rule ID | Exact matching behavior | Family | Severity | Threshold group |
| --- | --- | --- | --- | --- |
| `tcp_null_scan` | Explicit `NONE` only | `network_scanning` | medium | `TCP_FLAG_SCAN_*` |
| `tcp_xmas_scan` | Exactly `FIN,PSH,URG`; ECE/CWR extras are rejected | `network_scanning` | medium | `TCP_FLAG_SCAN_*` |
| `tcp_fin_scan` | Exactly `FIN` | `network_scanning` | medium | `TCP_FLAG_SCAN_*` |
| `tcp_ack_scan` | Exactly `ACK` | `network_scanning` | medium | Common diversity plus `TCP_ACK_SCAN_*` |
| `tcp_syn_fin_anomaly` | Contains `SYN` and `FIN` | `network_anomaly` | high | Common diversity plus `TCP_INVALID_COMBINATION_*` |
| `tcp_syn_rst_anomaly` | Contains `SYN` and `RST` | `network_anomaly` | medium | Common diversity plus `TCP_INVALID_COMBINATION_*` |
| `repeated_tcp_reset_anomaly` | Contains `RST` without `SYN` | `network_anomaly` | medium | `TCP_RESET_ANOMALY_*` |
| `spi_followed_by_allowed_connection` | Repeated explicit SPI blocks followed by a related allowed destination/service | `network_intrusion_candidate` | high | `SPI_THEN_ALLOWED_*` |

Common flag scans use a 300-second window, five events, three targets or three ports,
and a 0.60 blocked ratio. ACK scans require ten events and a 0.85 blocked ratio;
invalid SYN combinations require five events and a 0.80 blocked ratio. Repeated resets
use a 300-second window, ten events, three targets or ports, and a 0.60 blocked ratio.
The SPI sequence requires three preceding explicit SPI blocks within 600 seconds. The
allowed event must occur later for the same source, relate to an affected destination,
and use the same port or existing service profile; it remains signal evidence.

All 29 registered rules remain batch-local to one `DetectionEngine.analyze()` call.
TCP anomaly, probe, and SPI sequence evidence indicates suspicious network behavior;
it is not proof of successful authentication, exploitation, compromise, or execution.

## Determinism

Incidents and signals use a deterministic hashing mechanism (`generate_signal_id`, `generate_incident_id`) based on entities, temporal bounds, and correlated events. This ensures that processing the exact same batch of logs repeatedly produces exactly the same incidents.

## APIs

The Detection Engine runs automatically before the LLM triage agent is invoked, passing deterministically discovered `signals` and `candidate_evidence` to the LangGraph state.

A standalone `POST /detect/file` endpoint and `--detect-file` CLI option are available for testing detection logic without invoking LLM tokens.
