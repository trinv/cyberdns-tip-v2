# Architecture

## Target topology
```text
External Feeds
  |\
  | +--> CTI-worthy feeds --> OpenCTI
  |
  +----> bulk/category feeds --> PostgreSQL
                         \          /
                          \        /
                           Policy Engine
                                |
                         Blocklist Exporter
                                |
               +----------------+----------------+
               |                |                |
            Blocky-1         Blocky-2         Blocky-N
               |                |                |
               +---------- DNS upstream ----------+
```

## Plane separation
### Intelligence plane
OpenCTI. Store threat intelligence, relationships, source attribution, confidence, lifecycle, enrichment.

### Operational plane
PostgreSQL. Store normalized rules that can be enforced, plus source/category/audit/lifecycle metadata.

### Decision plane
Policy Engine. Convert indicators into BLOCK/MONITOR/ALLOW.

### Distribution plane
Blocklist Exporter. Convert effective enforcement dataset into versioned Blocky-compatible snapshots.

### Data plane
Blocky. Match DNS queries against in-memory lists. No database calls.

## Failure behavior
- OpenCTI down: DNS continues from existing PostgreSQL/exporter snapshots.
- PostgreSQL down: existing exporter snapshot continues serving.
- Exporter down: existing Blocky snapshot continues.
- New feed malformed: reject import, preserve last valid version.
- Snapshot build fails: do not replace current version.

## Scaling
Scale each plane independently. Add Blocky nodes for QPS/availability; add exporter workers for build throughput; add PostgreSQL replicas for read/export pressure; scale OpenCTI according to CTI ingestion/search/worker requirements.
