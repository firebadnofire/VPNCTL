PRAGMA foreign_keys = ON;

CREATE TABLE authority_meta (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
  appliance_id TEXT NOT NULL UNIQUE,
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  protocol_version INTEGER NOT NULL CHECK (protocol_version > 0),
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  lease_token TEXT,
  lease_owner TEXT,
  lease_scope TEXT,
  lease_base_revision INTEGER,
  lease_expires_at TEXT,
  CHECK (
    (lease_token IS NULL AND lease_owner IS NULL AND lease_scope IS NULL
      AND lease_base_revision IS NULL AND lease_expires_at IS NULL)
    OR
    (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_scope IS NOT NULL
      AND lease_base_revision IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);

CREATE TABLE vpn_instances (
  id TEXT PRIMARY KEY NOT NULL,
  model_json TEXT NOT NULL,
  deleted_at TEXT
);

CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  model_json TEXT NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  model_json TEXT NOT NULL,
  deleted_at TEXT
);

CREATE TABLE dns_records (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  model_json TEXT NOT NULL
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY NOT NULL,
  value_json TEXT NOT NULL
);

CREATE TABLE deployments (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  desired_state_json TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  backup_name TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE TABLE deployment_events (
  deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK (sequence >= 0),
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL,
  phase TEXT NOT NULL,
  message TEXT NOT NULL,
  technical_detail TEXT,
  PRIMARY KEY (deployment_id, sequence)
);

CREATE TABLE backup_records (
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  backend TEXT NOT NULL,
  reason TEXT NOT NULL,
  protects_identity INTEGER NOT NULL CHECK (protects_identity IN (0, 1)),
  deployment_id TEXT REFERENCES deployments(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (instance_id, name)
);

CREATE TABLE activity_events (
  id TEXT PRIMARY KEY NOT NULL,
  timestamp TEXT NOT NULL,
  severity TEXT NOT NULL,
  operation TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  technical_detail TEXT,
  instance_id TEXT REFERENCES vpn_instances(id) ON DELETE SET NULL,
  backend TEXT,
  deployment_id TEXT REFERENCES deployments(id) ON DELETE SET NULL
);

CREATE INDEX activity_events_timestamp ON activity_events(timestamp DESC);
CREATE INDEX activity_events_context
ON activity_events(instance_id, backend, operation, severity);

CREATE TABLE secrets (
  id TEXT PRIMARY KEY NOT NULL,
  owner_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  value BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX secrets_owner ON secrets(owner_id);

CREATE TABLE idempotency_records (
  key TEXT PRIMARY KEY NOT NULL,
  operation TEXT NOT NULL,
  committed_revision INTEGER NOT NULL CHECK (committed_revision > 0),
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
