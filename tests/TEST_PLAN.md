# Test Plan

## Unit
- domain normalization
- wildcard normalization
- parser per source
- source/category mapping
- scoring
- allowlist precedence
- expiry/lifecycle
- deterministic decision reason

## Integration
- PostgreSQL migrations
- staging/COPY merge
- idempotent re-import
- feed removal/grace period
- exporter snapshot generation
- manifest/checksum
- ETag/304
- Blocky feed consumption

## Resilience
- OpenCTI unavailable
- PostgreSQL unavailable after snapshot creation
- malformed feed
- partial download
- exporter crash during publish
- disk full
- network timeout

## Performance
Run 100K, 1M, 5M, 10M domain datasets. Capture CPU, RSS, I/O, time, QPS and p95/p99 latency.

## Security
- TLS verification
- authentication/token handling
- no public DB access
- path traversal protection on category API
- maximum response size
- safe logging
