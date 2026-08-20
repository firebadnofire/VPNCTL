PRAGMA foreign_keys = ON;

CREATE TABLE connections (
  id TEXT PRIMARY KEY NOT NULL,
  appliance_id TEXT UNIQUE,
  display_name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  ssh_port INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
  username TEXT NOT NULL,
  private_key_path TEXT NOT NULL,
  passphrase_secret_ref TEXT,
  model_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE approved_host_keys (
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL,
  public_key_base64 TEXT NOT NULL,
  sha256_fingerprint TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, algorithm)
);
