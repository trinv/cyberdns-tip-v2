# Implementation Specification

## Feed Ingestor
Implement adapter interface and source registry.

Pseudo-flow:
```text
scheduler
  -> source config
  -> conditional HTTP GET
  -> response validation
  -> hash
  -> parser
  -> normalization
  -> dedup
  -> staging table
  -> merge/upsert
  -> import audit
```

### Domain normalization
- lower-case ASCII domain names where appropriate.
- trim trailing dot for canonical storage.
- validate DNS label/hostname semantics.
- reject IPs in domain table; route to IP indicator tables if later implemented.
- preserve original raw value for audit when needed.
- wildcard: strip `*.` only for canonical storage and set `match_type=wildcard`.

### Import integrity
Reject a feed import when:
- TLS verification fails.
- response is larger than configured maximum.
- HTTP status is not acceptable.
- parser error rate exceeds configured threshold.
- the feed appears truncated or unexpectedly tiny.

## Policy Engine
Configuration example:
```yaml
policy:
  default_action: MONITOR
  categories:
    malware: {min_score: 70, action: BLOCK}
    phishing: {min_score: 70, action: BLOCK}
    scam: {min_score: 80, action: BLOCK}
    ads: {min_score: 50, action: BLOCK}
  source_trust:
    hagezi: 80
    urlhaus: 90
  independent_source_bonus: 10
  allowlist_overrides: true
```

Implement a pure decision function and exhaustive table-driven tests.

## Exporter
Preferred implementation:
1. read effective rules from PostgreSQL using a repeatable snapshot/read-only transaction or replica.
2. render to temp file.
3. validate line count/checksum.
4. fsync.
5. atomic rename.
6. update manifest.
7. expose immediately.

Keep previous snapshot for rollback.

## OpenCTI connector boundary
Only CTI-worthy data goes into OpenCTI. Where a source is a plain-text list, implement a custom import connector that converts records into STIX 2.1 objects rather than assuming the raw file is a STIX feed.

For sources that already provide TAXII/STIX, use native OpenCTI TAXII/connector mechanisms before writing custom code.
