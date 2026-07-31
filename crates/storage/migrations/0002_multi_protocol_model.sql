PRAGMA foreign_keys = ON;

ALTER TABLE vpn_instances
ADD COLUMN instance_schema_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE vpn_instances
ADD COLUMN backend_settings_json TEXT NOT NULL
DEFAULT '{"backend":"wireguard","settings":{"userspace_fallback":false}}';

ALTER TABLE devices
ADD COLUMN identity_schema_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE devices
ADD COLUMN backend TEXT NOT NULL DEFAULT 'wireguard';

DROP INDEX vpn_instances_host_port_active;

CREATE TABLE instance_listeners (
  instance_id TEXT NOT NULL REFERENCES vpn_instances(id) ON DELETE CASCADE,
  host_id TEXT NOT NULL REFERENCES docker_hosts(id) ON DELETE CASCADE,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport TEXT NOT NULL CHECK (transport IN ('tcp', 'udp')),
  active INTEGER NOT NULL CHECK (active IN (0, 1)),
  PRIMARY KEY (instance_id, port, transport)
);

CREATE UNIQUE INDEX instance_listeners_host_port_transport_active
ON instance_listeners(host_id, port, transport) WHERE active = 1;

INSERT INTO instance_listeners (instance_id, host_id, port, transport, active)
SELECT id, host_id, endpoint_port, 'udp',
       CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END
FROM vpn_instances;

DROP INDEX devices_instance_address_active;

CREATE UNIQUE INDEX devices_instance_address_active
ON devices(instance_id, ipv4_address)
WHERE deleted_at IS NULL AND ipv4_address <> '';
