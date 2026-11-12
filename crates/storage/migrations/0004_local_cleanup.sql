-- Recovery material must not depend on an active connection profile.
CREATE TABLE local_host_recovery (
  host_id TEXT PRIMARY KEY NOT NULL,
  identity_json TEXT,
  recovery_json TEXT NOT NULL,
  preserved_at TEXT NOT NULL
);

-- Receipts survive profile deletion and make retries independent of host rows.
CREATE TABLE local_cleanup_operations (
  id TEXT PRIMARY KEY NOT NULL,
  scope_json TEXT NOT NULL,
  completed_at TEXT NOT NULL
);

CREATE TABLE local_recovery_secret_references (
  id TEXT PRIMARY KEY NOT NULL,
  host_id TEXT NOT NULL REFERENCES local_host_recovery(host_id)
);
