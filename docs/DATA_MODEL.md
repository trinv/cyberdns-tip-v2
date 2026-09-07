# Data Model

## Domain rule
```sql
CREATE TABLE domains (
  id BIGSERIAL PRIMARY KEY,
  domain TEXT NOT NULL,
  normalized_domain TEXT NOT NULL,
  match_type SMALLINT NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(normalized_domain, match_type)
);
```

## Sources
```sql
CREATE TABLE sources (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  url TEXT,
  source_type TEXT NOT NULL,
  trust_score SMALLINT NOT NULL DEFAULT 50,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  refresh_interval_seconds INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Categories
```sql
CREATE TABLE categories (
  id SMALLSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);
```

## Relationships
```sql
CREATE TABLE domain_sources (
  domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  source_id BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  confidence SMALLINT,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(domain_id, source_id)
);

CREATE TABLE domain_categories (
  domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  category_id SMALLINT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  score SMALLINT NOT NULL DEFAULT 0,
  PRIMARY KEY(domain_id, category_id)
);
```

## Allowlist
```sql
CREATE TABLE allowlist (
  domain TEXT NOT NULL,
  match_type SMALLINT NOT NULL DEFAULT 0,
  reason TEXT,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY(domain, match_type)
);
```

## Feed import audit
```sql
CREATE TABLE feed_imports (
  id BIGSERIAL PRIMARY KEY,
  source_id BIGINT REFERENCES sources(id),
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  feed_hash TEXT,
  total_records BIGINT DEFAULT 0,
  accepted_records BIGINT DEFAULT 0,
  rejected_records BIGINT DEFAULT 0,
  added_records BIGINT DEFAULT 0,
  updated_records BIGINT DEFAULT 0,
  removed_records BIGINT DEFAULT 0,
  status TEXT NOT NULL,
  error_message TEXT
);
```

## Match type contract
- `0 = exact`
- `1 = wildcard`
- `2 = regex`

Exporter must render each match type to the target Blocky feed format.
