# Security and secret lifecycle

## Secret locations

| Material | Location | SQLite/frontend |
| --- | --- | --- |
| SSH key passphrase | macOS Keychain | opaque reference only |
| Device private key | generated locally, macOS Keychain | opaque reference only |
| Device preshared key | generated locally, macOS Keychain | opaque reference only |
| Server private key | remote `vpn/server.key`, mode `0600` | never present |
| Server public key | remote manifest and local secure reference | public value |
| Client configuration | generated transiently in Rust | never serialized to frontend |

There is no plaintext secret-store fallback.

## Device identity

Export and QR generation reuse the existing device key. Regeneration does not silently rotate it. If Keychain material is missing, the application reports an irrecoverable identity and requires explicit replacement followed by deployment.

Deletion marks secret references pending. Keychain values are removed only after they are absent from the ten newest deployment snapshots.

## Remote server key

The application uploads a sentinel-bearing template. Inside the pinned WireGuard container, a shell creates or reuses `server.key`, prints only `wg pubkey`, and uses `awk` to read the private key from the file while materializing `wg0.conf`. The private key is not returned, uploaded, logged, persisted locally, or placed in process arguments.

## Logs and error detail

Redaction removes known secret values and any line identified as a private key, preshared key, password, or passphrase. Sensitive rendered files are never returned by Tauri or printed by `vam-dev`. Operational events contain phases and safe diagnostics, not raw secret-bearing commands.

Report vulnerabilities privately to the repository owner. Do not include real configurations, private keys, or passphrases in reports.
