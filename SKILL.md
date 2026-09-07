# SKILL.md — Implementation Skill

## Role
You are implementing a scalable DNS Firewall control/data plane. Optimize for correctness, deterministic behavior, low operational risk, and measured performance.

## Core workflow
1. Inspect repository state and existing code before changes.
2. Read `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API.md`, and `PLAN.md`.
3. Implement one vertical slice at a time.
4. Add tests before/with each feature.
5. Run formatting, unit tests, integration tests, and targeted benchmarks.
6. Keep changes small and reversible.
7. Update ADRs for architectural changes.

## Feed adapter contract
Every adapter must implement conceptually:
- `Fetch(ctx) -> RawFeed`
- `Validate(raw) -> ValidationResult`
- `Parse(raw) -> []CanonicalIndicator`
- `Metadata() -> SourceMetadata`

Required behavior:
- Conditional HTTP requests when supported.
- Max response size.
- TLS verification.
- timeout.
- retry with backoff.
- checksum/hash.
- malformed-line counters.
- deterministic normalization.
- stable source/feed identifiers.

## Canonical indicator
Minimum fields:
- domain
- normalized_domain
- match_type
- category[]
- source_id
- confidence
- first_seen
- last_seen
- expires_at
- raw_hash
- active

## Policy engine
Policy must be deterministic and side-effect free.
Inputs:
- source trust score
- confidence
- independent source count
- category weight
- recency
- expiry
- allowlist
- manual override

Outputs:
- action: BLOCK | MONITOR | ALLOW
- effective_score
- matched_rules
- explain string/reason code

## PostgreSQL
Use staging + COPY for large imports. Merge into normalized tables. Prefer batched upserts. Do not implement arbitrary substring or regex matching in the DNS path.

## Exporter
- Generate snapshots off the query path.
- Write temp files.
- fsync when appropriate.
- atomic rename.
- keep at least one previous known-good version.
- expose `/healthz`, `/readyz`, `/metrics`, `/v1/manifest`, `/v1/blocklists/{category}.txt`.
- support ETag/Last-Modified and return 304 when possible.

## Blocky integration
- HTTPS feed endpoints only.
- Category feeds preferred over a single monolithic file when operationally useful.
- Preserve snapshot version in metrics and manifest.
- Test reload behavior and rollback before production.

## Safety
Never silently convert parser errors into blocked domains. A malformed or partially downloaded feed must fail closed for the import operation while preserving the last valid snapshot. For high-impact categories, use multi-source confirmation or explicit policy thresholds.
