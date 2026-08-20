CREATE TABLE authority_snapshots (
  appliance_id TEXT PRIMARY KEY NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  protocol_version INTEGER NOT NULL CHECK (protocol_version >= 0),
  schema_version INTEGER NOT NULL CHECK (schema_version >= 0),
  software_version TEXT NOT NULL,
  synchronized_at TEXT NOT NULL,
  snapshot_json TEXT NOT NULL
);
