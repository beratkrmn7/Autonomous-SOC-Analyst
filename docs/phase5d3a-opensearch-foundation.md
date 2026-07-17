# Phase 5D.3A — Optional OpenSearch foundation

Phase 5D.3A adds a secure, optional OpenSearch foundation. PostgreSQL remains
the source of truth and all existing public search endpoints continue to use
the Phase 5D.1 database repositories. This phase does **not** add indexing,
outbox processing, workers, query translation, reindexing, deletion, rollover,
ISM, alias cutover, a public endpoint, or automatic startup bootstrap.

## Compatibility decision

The project uses `opensearch-py>=3.2,<4`. The official
[client compatibility matrix](https://github.com/opensearch-project/opensearch-py/blob/main/COMPATIBILITY.md)
states that the 3.x Python client supports OpenSearch 1.x through 3.x, provided
an older cluster is not asked to use features removed in 3.0. The foundation
therefore recognizes cluster major versions 1, 2, and 3 and treats other majors
as incompatible. CI remains on Python 3.11; the selected package
[metadata](https://pypi.org/project/opensearch-py/) supports Python 3.10
through 3.x.

## Safe defaults and configuration

OpenSearch is disabled by default. Configure it with environment variables:

| Variable | Default | Safety behavior |
| --- | --- | --- |
| `OPENSEARCH_ENABLED` | `false` | No client or network operation while disabled |
| `OPENSEARCH_REQUIRED` | `false` | If true, readiness requires a healthy foundation |
| `OPENSEARCH_HOSTS` | `["https://localhost:9200"]` | HTTP(S) origins only; credentials, path, query, and fragment are rejected |
| `OPENSEARCH_USERNAME` / `OPENSEARCH_PASSWORD` | unset | Must be configured together; password is a secret value |
| `OPENSEARCH_CA_CERTS` | unset | Optional CA bundle |
| `OPENSEARCH_CLIENT_CERT` / `OPENSEARCH_CLIENT_KEY` | unset | Optional mTLS pair; must be configured together |
| `OPENSEARCH_VERIFY_CERTS` | `true` | Cannot be disabled in production |
| `OPENSEARCH_CONNECT_TIMEOUT_SECONDS` | `3` | Bounded to 30 seconds |
| `OPENSEARCH_READ_TIMEOUT_SECONDS` | `10` | Bounded to 120 seconds |
| `OPENSEARCH_MAX_RETRIES` | `2` | Bounded to five retries |
| `OPENSEARCH_POOL_MAXSIZE` | `10` | Bounded connection pool |
| `OPENSEARCH_INDEX_PREFIX` | `agentic-soc` | Lowercase hyphenated name only |
| `OPENSEARCH_SCHEMA_VERSION` | `v1` | Explicit `vN` schema version |
| `OPENSEARCH_NUMBER_OF_SHARDS` | `1` | Bounded index setting |
| `OPENSEARCH_NUMBER_OF_REPLICAS` | `0` | Bounded index setting |
| `OPENSEARCH_MAPPING_TOTAL_FIELDS_LIMIT` | `256` | Bounded mapping growth |
| `OPENSEARCH_BOOTSTRAP_ON_STARTUP` | `false` | Any attempt to enable it is rejected |

Production additionally requires HTTPS hosts and certificate verification.
The zero-replica default is intended for local single-node use; operators must
choose an appropriate replica count for their production availability model.
The official client is created lazily with request compression, bounded
connection pooling, TLS/auth/mTLS options, connect/read timeouts, retry on
timeout, and retries only for 429/502/503/504. Errors are converted to stable
codes; credentials, host URLs, exception text, and response bodies are not
included in health or CLI output.

## Index and alias contract

The versioned physical index names are:

```text
{prefix}-canonical-events-{schema}-000001
{prefix}-detection-signals-{schema}-000001
{prefix}-incidents-{schema}-000001
```

Each logical index has `{prefix}-{logical}-read` and
`{prefix}-{logical}-write` aliases. Both point to the same initial physical
index; only the write alias is marked `is_write_index=true`.

Mappings use `dynamic: strict`, a bounded total field count, explicit types,
and deterministic SHA-256 fingerprints stored in mapping metadata. IDs,
statuses, categories, MITRE techniques, and relationship IDs are `keyword`;
IP addresses use `ip`; ports use `integer`; timestamps use `date`; confidence
uses `float`; and only controlled display/search fields use `text` with a
bounded keyword subfield. No unrestricted object or dynamic template exists.

## Safe document contracts

Typed serializers exist for canonical events, detection signals, and
incidents. They copy an explicit allowlist from ORM rows, normalize UTC
timestamps and IP addresses, validate ports/confidence, cap and redact text,
deduplicate bounded string lists, and emit deterministic JSON. They omit raw
records, raw hashes, source lines, original fields, arbitrary metrics, review
material, provider data, prompts, tokens, and all other unrestricted payloads.

The documents include only the safe relationship projections needed by a
future Phase 5D.3 search adapter: job/incident/context IDs and the incident
report/evidence flags. These serializers do not write documents in this phase.

## Read-only plan and fail-closed bootstrap

Use the maintenance module explicitly:

```powershell
python -m agent.maintenance.opensearch check
python -m agent.maintenance.opensearch plan
python -m agent.maintenance.opensearch bootstrap
```

`check` reports a sanitized status. `plan` is read-only and reports one of:

- `missing`
- `ready`
- `mapping_drift`
- `settings_drift`
- `alias_missing`
- `alias_drift`
- `unexpected_alias_target`
- `incompatible_schema`

`bootstrap` first builds the plan. It creates only a missing versioned index
and adds only a missing expected alias. Alias additions for a run use one
atomic add-only request. It never edits mappings/settings, removes or retargets
aliases, deletes indices/documents, reindexes, or performs a cutover. Any drift
aborts before mutation. A postcondition plan must be fully ready. Re-running a
successful bootstrap returns zero changes.

Index creation and alias creation are separate OpenSearch operations. A failure
after an index is created can leave that safe, unused versioned index present;
the next explicit run inspects it and resumes by adding only verified missing
aliases. It never rolls back by deleting or mutating existing resources.

## Health and operations

The existing readiness response includes an `opensearch` component only when
OpenSearch is enabled. Optional OpenSearch degradation does not make the API
unready. When `OPENSEARCH_REQUIRED=true`, any result other than `healthy`
returns not-ready. Liveness never contacts OpenSearch.

Bootstrap is deliberately an operator command, not an application startup
hook. Review the read-only plan first, then run bootstrap using an identity with
only the cluster inspection, index creation, and alias-add permissions needed
for this foundation. No Docker or deployment assumptions are introduced.

## Deferred work

Document indexing, durable outbox/event delivery, workers and schedulers,
OpenSearch query builders, switching the Phase 5D.1 backend, reindex workflows,
delete/tombstone coordination, aliases cutover, rollover/ISM, and archive/search
lifecycle coordination remain future phases.
