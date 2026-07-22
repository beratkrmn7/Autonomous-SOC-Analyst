# Real-log triage behavior

This document describes the deterministic hardening applied after replaying representative
PF firewall logs through ingestion, detection, persistence, correlation, routing, and CLI
reporting. It records operational behavior, not a new detection phase.

## Canonical event continuity

Detection and triage must see the same structured event facts. The persistence boundary
therefore round-trips the explicit canonical fields used by both layers:

- action reason and normalized TCP flags;
- inbound/outbound interfaces and zones;
- NAT type and translated source/destination addresses and ports;
- bytes, packets, and duration;
- bounded source and destination FQDN collections; and
- an allowlisted, bounded, JSON-safe parser-metadata subset.

Arbitrary parser metadata and raw records are not persisted through this mapping. Existing
rows remain valid because the migration adds nullable columns and requires no backfill.

## Incident identity and overlap

Signals keep their registered rule contract and historical service-specific variants. The
incident layer applies these conventions:

- exposure and firewall-policy incidents are owned by the effective destination asset;
- scan and service-probe incidents are owned by the observed source;
- titles always obtain `from <source IP>` independently of `primary_entity`; and
- effective destination is the translated destination when present, otherwise the original
  destination.

After normal cross-rule correlation, incidents with the same type and primary entity are
merged when their windows overlap or touch and their event sets are nested or have Jaccard
overlap of at least 0.5. The keeper is selected by event-set size, then first-seen time,
then incident ID. Sets and evidence are unioned deterministically and evidence stays bounded.

## Cross-job provenance and isolation

Persistent cross-job correlation is optional and controlled by
`STATEFUL_CORRELATION_ENABLED`. When it is used, final incident metrics state:

- `contributing_job_count`;
- `current_job_event_count`; and
- `prior_job_event_count`.

The CLI renders this breakdown instead of presenting historical events as if they all came
from the current file. `--isolated` disables stateful resolution for that run through the
existing resolver guard. Because this changes analysis behavior, isolated and configured
correlation have different idempotency scopes. `--report brief|full` changes presentation
only and is deliberately excluded from the idempotency key.

A completed-job replay returns persisted results and performs no provider call.

## Family-aware severity

Severity is derived from typed canonical-event facts at the layer where the incident's
events are available. The policy distinguishes security conclusion from rule confidence:

- fully blocked scan/probe activity is low, or medium for at least 25 distinct targets;
- allowed access to a standard service is medium;
- allowed access to a sensitive service is high;
- allowed access to a critical management service is critical; and
- unrelated incident families retain their existing signal-driven behavior.

An allowed firewall event proves policy exposure only. It does not prove that an
application session, login, exploit, or compromise succeeded. Service sensitivity also
does not assert business asset criticality.

The sensitive port set is `20, 21, 22, 23, 135, 139, 389, 445, 1433, 3306, 3389,
5432, 5900`. The critical management set is `161, 623, 2375, 5985, 6379, 9200,
10250, 11211, 27017`. Port 20 is labelled `ftp_data`; port 21 is `ftp`.

## Exposure recall

Inbound sensitive-service detection accepts one allowed event by default. WAN-to-LAN
evaluation prefers explicit zones and, only when the outbound zone is absent, uses the
shared deterministic flow-direction helper. Effective translated destinations remain
visible without mutating the canonical event.

## Structural late-RST suppression

Suppression receives an immutable event lookup during detection. An SPI anomaly is
classified as `late_rst_from_established_service` only when it contains at least two
contributing events and every event:

- is an explicit SPI block;
- shares one well-known source port from `22, 53, 80, 443, 993, 995`;
- targets a unique ephemeral destination port at or above 32768;
- targets exactly one destination IP; and
- has normalized flags exactly `RST` or `RST+ACK`.

Near misses remain unsuppressed. Organization or provider ownership is never a suppression
input. Suppressed findings remain visible in the brief.

## SOC rollup and brief

`agent/detection/rollup.py` is a pure presentation layer over canonical incidents and
event facts. It produces bounded `act_now` and `investigate` lists, compatible blocked
recon groups, suppressed entries, an exposed-asset inventory, and a funnel.

Recon grouping requires every contributing incident to be fully blocked, compatible
family and service/port scope, and compatible time. A shared network prefix alone is not
sufficient. Passed or mixed-action activity remains actionable or investigatory.

`python main.py --file <path> --report brief` renders the rollup with Rich. The brief:

- uses the source event's original timezone offset;
- shows evidence IDs and cross-job provenance;
- shows suppressed and duplicate counts in the funnel;
- renders existing deterministic facts and existing report results; and
- never invokes a provider itself.

`--report full` preserves the detailed per-incident panels. Neither report mode changes
canonical incidents, persistence, routing, identities, or provider policy.

## Provider boundary

Ingestion, detection, suppression, correlation, rollup, brief rendering,
`deterministic_report`, `digest`, `store_only`, and completed-job replay make zero provider
calls. Only `individual_triage` may reach the configured provider, at most once per unique
final canonical incident in a fresh job.

## Verification

Focused regression coverage includes persistence round trips and migration topology,
overlap merging, stateful provenance, isolated idempotency, family-aware severity,
exposure recall, late-RST near misses, rollup safety, incident entity semantics,
deterministic briefs, and provider-call boundaries. Full repository gates run in GitHub
Actions.
