# PLAN.md — Execution Plan

## Phase 0 — Repository bootstrap
### Tasks
- Create service modules: `feed-ingestor`, `policy-engine`, `blocklist-exporter`.
- Create DB migration framework.
- Add Docker Compose for local development.
- Add CI for lint/test/build.
- Add Prometheus metrics baseline.

### Done when
- `go test ./...` passes.
- local stack starts with one command.
- migrations are repeatable.

## Phase 1 — End-to-end MVP without OpenCTI
### Sources
- HaGeZi TIF (primary CTI feed).
- One bulk blocklist feed.

### Pipeline
Feed -> parser -> PostgreSQL -> policy -> exporter -> 2 Blocky containers.

### Required features
- domain normalization
- exact/wildcard
- source/category
- idempotent import
- allowlist
- snapshot generation
- ETag/Last-Modified
- Blocky refresh

### Done when
- E2E test proves a blocked domain is denied by Blocky.
- allowlisted domain is not denied.
- source removal/deactivation does not delete immediately; lifecycle is observable.

## Phase 2 — OpenCTI integration
### Tasks
- Deploy OpenCTI for PoC.
- Implement/activate dedicated connector for CTI feeds.
- Map source organization and labels.
- Map DomainName/Indicator semantics.
- Preserve first/last seen and confidence where available.
- Establish CTI qualification boundary: only CTI-worthy indicators enter OpenCTI.

### Done when
- At least 100K CTI indicators imported successfully.
- connector health monitored.
- source attribution verified.

## Phase 3 — Policy engine
### Tasks
- Implement configurable scoring.
- Implement source trust weights.
- Implement independent-source bonus.
- Implement category weights.
- Implement TTL/expiry.
- Implement manual allowlist/override.
- Implement decision explainability.

### Done when
- 100% deterministic test suite for decision matrix.
- audit record explains every BLOCK/ALLOW.

## Phase 4 — Scale benchmark
Run datasets:
- 100K
- 1M
- 5M
- 10M

Measure:
- feed fetch time
- parse time
- PostgreSQL ingest time
- DB size
- exporter build time
- snapshot size
- Blocky reload time
- Blocky RSS
- CPU
- DNS p95/p99 latency
- update propagation time

### Gate
Do not move to production until benchmark data is captured and sizing is evidence-based.

## Phase 5 — HA/production hardening
- PostgreSQL backups/PITR.
- PostgreSQL replica for export/reporting if required.
- OpenCTI HA only if workload requires it.
- Exporter HA.
- 3+ Blocky nodes per site where appropriate.
- Anycast/LB integration.
- monitoring/alerts.
- failover tests.
- snapshot rollback tests.
- security review.

## Phase 6 — Additional feeds
Add one source at a time:
- URLhaus
- phishing feeds
- CERT feeds
- MISP/TAXII
- regional feeds

For each new source:
1. add adapter
2. fixture tests
3. source trust default
4. category mapping
5. anomaly thresholds
6. benchmark delta
7. run in shadow mode
8. enable blocking after validation
