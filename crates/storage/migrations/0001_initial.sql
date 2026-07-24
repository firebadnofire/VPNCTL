PRAGMA foreign_keys = ON;

CREATE TABLE docker_hosts (
  id TEXT PRIMARY KEY NOT NULL,
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

CREATE TABLE known_host_keys (
  host_id TEXT NOT NULL REFERENCES docker_hosts(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL,
  public_key_base64 TEXT NOT NULL,
  sha256_fingerprint TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  PRIMARY KEY (host_id, algorithm)
);

CREATE TABLE vpn_instances (
  id TEXT PRIMARY KEY NOT NULL,
  host_id TEXT NOT NULL REFERENCES docker_hosts(id) ON DELETE RESTRICT,
  display_name TEXT NOT NULL,
  backend TEXT NOT NULL,
  endpoint_port INTEGER NOT NULL CHECK (endpoint_port BETWEEN 1 AND 65535),
  ipv4_subnet TEXT NOT NULL,
  dns_zone TEXT NOT NULL,
  model_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE UNIQUE INDEX vpn_instances_host_port_active
ON vpn_instances(host_id, endpoint_port) WHERE deleted_at IS NULL;

CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL,
  model_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE RESTRICT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  ipv4_address TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  model_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE UNIQUE INDEX devices_instance_address_active
ON devices(instance_id, ipv4_address) WHERE deleted_at IS NULL;

CREATE TABLE dns_records (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  record_type TEXT NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER NOT NULL CHECK (ttl BETWEEN 30 AND 86400),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  managed_by_device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  model_json TEXT NOT NULL
);

CREATE TABLE deployments (
  id TEXT PRIMARY KEY NOT NULL,
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE RESTRICT,
  status TEXT NOT NULL,
  desired_state_json TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  backup_name TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE TABLE deployment_events (
  deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL,
  phase TEXT NOT NULL,
  message TEXT NOT NULL,
  technical_detail TEXT,
  PRIMARY KEY (deployment_id, sequence)
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY NOT NULL,
  value_json TEXT NOT NULL
);

CREATE TABLE secret_references (
  id TEXT PRIMARY KEY NOT NULL,
  purpose TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  pending_delete_at TEXT
);
