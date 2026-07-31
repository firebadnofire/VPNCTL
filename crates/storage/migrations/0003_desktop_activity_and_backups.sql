PRAGMA foreign_keys = ON;

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
  host_id TEXT REFERENCES docker_hosts(id) ON DELETE SET NULL,
  instance_id TEXT REFERENCES vpn_instances(id) ON DELETE SET NULL,
  backend TEXT,
  deployment_id TEXT REFERENCES deployments(id) ON DELETE SET NULL
);

CREATE INDEX activity_events_timestamp ON activity_events(timestamp DESC);
CREATE INDEX activity_events_context ON activity_events(instance_id, host_id, backend, operation, severity);
