# CLAUDE.md — Threat Intelligence-Driven DNS Firewall

## Mission
Implement a production-grade Threat Intelligence-driven DNS Firewall using:
- OpenCTI for CTI knowledge/intelligence.
- PostgreSQL for operational enforcement data.
- Policy Engine for deterministic block/allow decisions.
- Blocklist Exporter for immutable, versioned Blocky-compatible feeds.
- Blocky as the DNS data-plane enforcement engine.

## Non-negotiable architecture rules
1. Never query OpenCTI or PostgreSQL from the DNS request path.
2. Never make DNS availability depend on OpenCTI availability.
3. Never treat OpenCTI as the primary bulk blocklist database.
4. Normalize every source into a canonical IOC/rule model before storage.
5. Represent `domain` and `match_type` independently; do not encode wildcard semantics only in the domain string.
6. Publish blocklists as immutable/versioned snapshots and use atomic replacement.
7. Preserve a last-known-good snapshot on every Blocky node.
8. Every feed import must be auditable: source, version/hash, timestamps, counts, errors.
9. Every blocking decision must be explainable by policy/source/category/confidence.
10. Prefer exact and wildcard rules; use regex only when explicitly justified and tested.
11. Do not introduce Kafka, Kubernetes, or other infrastructure before benchmark evidence requires it.
12. All new code must include unit and integration tests and Prometheus metrics.

## Delivery order
Follow `PLAN.md` sequentially. Do not skip performance testing before production sizing.

## Coding standards
- Go for high-throughput services.
- Python is acceptable for PoC-only adapters when it materially reduces implementation time.
- Configuration via YAML/env; secrets via environment/secret store, never hard-coded.
- Structured JSON logs.
- Context-aware timeouts and cancellation.
- Retries with exponential backoff and jitter.
- Idempotent imports.
- PostgreSQL transactions around logical batches, not entire multi-million-record feeds.
- Use COPY/staging tables for bulk loads.
- Avoid N+1 queries.

## Required repository checks
Before marking any phase complete:
- `go test ./...`
- integration tests against PostgreSQL
- feed parser fixture tests
- policy decision tests
- exporter snapshot consistency tests
- HTTP conditional GET tests (ETag/304)
- benchmark output captured under `tests/performance/results/`
- documentation updated when APIs/config change

## Current source references
OpenCTI docs:
- https://docs.opencti.io/latest/deployment/overview/
- https://docs.opencti.io/latest/deployment/connectors/
- https://docs.opencti.io/latest/deployment/integrations/
- https://docs.opencti.io/latest/usage/import/csv-feed/
- https://docs.opencti.io/latest/usage/import/taxii-feed/
- https://docs.opencti.io/latest/usage/import/getting-started/

HaGeZi:
- https://github.com/hagezi/dns-blocklists
- https://github.com/hagezi/dns-blocklists/blob/main/sources.md

Blocky:
- https://0xerr0r.github.io/blocky/latest/
