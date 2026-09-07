# ADR-001: Split Intelligence and DNS Enforcement

## Status
Accepted

## Decision
OpenCTI and PostgreSQL are separate responsibilities. OpenCTI is the intelligence/knowledge layer. PostgreSQL is the operational enforcement store. Blocky remains isolated as the DNS data plane.

## Rationale
- Avoid database latency on DNS requests.
- Avoid forcing bulk blocklist data through STIX/graph infrastructure.
- Allow independent scaling.
- Allow OpenCTI outages without DNS outages.
- Preserve explainability and lifecycle in CTI while keeping enforcement simple.
