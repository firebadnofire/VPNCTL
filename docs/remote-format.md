# Remote format

## Paths

Each instance is UUID-derived:

```text
/opt/vpn-appliance-manager/
├── instances/<instance-uuid>/
│   ├── compose.yaml
│   ├── .env
│   ├── instance.json
│   ├── state.json
│   ├── vpn/
│   │   ├── server.key
│   │   ├── wg0.conf
│   │   └── wg0.conf.template
│   └── dns/
│       ├── Corefile
│       └── zones/db.<private-zone>
├── staging/<instance-uuid>-<deployment-uuid>/
├── backups/<instance-uuid>/<UTC-timestamp>/
└── trash/
```

Display names never participate in remote paths or Compose project names. `server.key` and materialized WireGuard configuration use mode `0600`.

## Images

```text
ghcr.io/linuxserver/wireguard:1.0.20260223-r0-ls118@sha256:2868ae5e3dd9065ea3b1e44b4214b33b02b7ce5ebcb9e4f33e1132b75007f39c
docker.io/coredns/coredns:1.14.6@sha256:900f9c109f7a33545d3c811516e8376df9019147b750f5ce3e254468769176ea
```

WireGuard receives a supplied `/config/wg_confs/wg0.conf`, `NET_ADMIN`, forwarding sysctls, and fixed forwarding/NAT rules. Peer generation and configuration logging are disabled.

CoreDNS shares the gateway network namespace. The private zone uses `auto`; all other queries forward only over TLS to `1.1.1.1` and `1.0.0.1` with `one.one.one.one` verification. There is no plaintext DNS downgrade.

## Manifest and drift

`state.json` mirrors deployment version, redacted file hashes, the server public key, and deployment time. Planning recomputes current remote hashes. WireGuard private and preshared lines are normalized before hashing; their values cannot enter the manifest.

Unexpected hash changes are reported as drift and replaced through a reviewed plan. Unsafe paths in a remote manifest are rejected before command construction.

## DNS

Records sort by owner, type, value, and UUID. Supported types are A, AAAA, CNAME, TXT, and SRV. Owner names remain inside the private zone. TTL is constrained to 30–86400 seconds. Each change increments a monotonic `YYYYMMDDNN` SOA serial; rollback creates a new serial.
