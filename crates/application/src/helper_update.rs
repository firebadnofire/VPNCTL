use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_ssh::UploadRequest;

use super::{AppError, ApplicationService, shell_quote, ssh_error};

/// Immutable Linux executable embedded by the trusted desktop build.
#[derive(Clone)]
pub struct HelperPayload {
    pub architecture: &'static str,
    pub contents: &'static [u8],
}

const REQUIRED: [&str; 3] = [
    vam_authority::manifest::INSTANCE_ARCHIVE_CAPABILITY,
    vam_authority::manifest::DROP_PEER_CAPABILITY,
    vam_authority::manifest::blocking::CAPABILITY,
];

fn update_error(message: &str) -> AppError {
    AppError {
        code: "helper_update_failed".into(),
        message: message.into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Refresh / Reconnect to retry. The SSH account needs passwordless sudo for helper installation. VPN configuration and running services are not deployed by this repair.".into()),
        technical_detail: None,
    }
}

fn payload_valid(payload: &HelperPayload) -> bool {
    let machine = match payload.architecture {
        "x86_64" => [62, 0],
        "aarch64" => [183, 0],
        _ => return false,
    };
    let bytes = payload.contents;
    bytes.len() >= 64
        && bytes.len() <= 150 * 1024 * 1024
        && &bytes[..6] == b"\x7fELF\x02\x01"
        && bytes[18..20] == machine
}

impl ApplicationService {
    /// Run only on explicit connection/synchronization, after normal identity checks.
    /// Feature supersets are left alone; this is not a version-based downgrade.
    pub(super) async fn ensure_remote_helper(&self, host_id: Uuid) -> Result<(), AppError> {
        let Some(payloads) = &self.helper_payloads else {
            // Non-desktop callers retain their separately administered helper workflow.
            return Ok(());
        };
        let _cleanup = self.cleanup_guard.read().await;
        let lock = self.instance_lock(host_id).await;
        let _guard = lock.lock().await;
        let before = self.remote_identity(host_id).await?;
        if REQUIRED
            .iter()
            .all(|required| before.capabilities.iter().any(|c| c == required))
        {
            return Ok(());
        }
        let (host, trusted, passphrase) = self.trusted_host(host_id).await?;
        let cancellation = CancellationToken::new();
        let probe = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                "uname -s; uname -m",
                &cancellation,
            )
            .await
            .map_err(ssh_error)?;
        let platform = probe.stdout_text().map_err(ssh_error)?;
        let architecture = match (probe.exit_status, platform.trim()) {
            (0, "Linux\nx86_64") => "x86_64",
            (0, "Linux\naarch64") => "aarch64",
            _ => {
                return Err(update_error(
                    "Automatic helper repair supports Linux x86_64 and aarch64 servers. Install a matching helper for this server platform.",
                ));
            }
        };
        let payload = payloads.iter().find(|p| p.architecture == architecture)
            .filter(|p| payload_valid(p))
            .ok_or_else(|| update_error("This desktop build has no valid bundled Linux helper for the server. Install a complete VPNCTL release or rebuild with helper bundles."))?;
        let installed = self.transport.execute(
            &host.ssh, &trusted.public_key_base64, passphrase.as_ref(),
            "/usr/bin/sudo -n -- /bin/sh -c 'PATH=/usr/bin:/bin; export PATH; sha256sum /usr/local/libexec/vam-server'",
            &cancellation,
        ).await.map_err(ssh_error)?;
        let installed_text = installed.stdout_text().map_err(ssh_error)?;
        let fields: Vec<_> = installed_text.split_whitespace().collect();
        if installed.exit_status != 0
            || fields.len() != 2
            || fields[1] != "/usr/local/libexec/vam-server"
            || fields[0].len() != 64
            || !fields[0].bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(update_error(
                "Could not verify the installed helper checksum. Check passwordless sudo, coreutils, and helper file permissions, then Refresh / Reconnect.",
            ));
        }
        let previous_digest = fields[0].to_ascii_lowercase();
        let stage = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                "umask 077; mktemp -d /tmp/vpnctl-helper.XXXXXXXXXX",
                &cancellation,
            )
            .await
            .map_err(ssh_error)?;
        let path = stage.stdout_text().map_err(ssh_error)?.trim().to_owned();
        if stage.exit_status != 0 || !valid_stage(&path) {
            return Err(update_error(
                "Could not create a private staging directory for helper repair. Check free space and /tmp permissions.",
            ));
        }
        let uploaded = self
            .transport
            .upload(UploadRequest {
                config: &host.ssh,
                trusted_key_base64: &trusted.public_key_base64,
                passphrase: passphrase.as_ref(),
                remote_path: &format!("{path}/vam-server"),
                contents: payload.contents,
                mode: 0o600,
                cancellation: &cancellation,
            })
            .await;
        let result = if let Err(error) = uploaded {
            Err(ssh_error(error))
        } else {
            let digest = format!("{:x}", Sha256::digest(payload.contents));
            let command = format!(
                "/usr/bin/sudo -n -- /bin/sh -c {} vpnctl-helper-update {} {} {}",
                shell_quote(include_str!("helper_install.sh")),
                shell_quote(&path),
                shell_quote(&digest),
                shell_quote(&previous_digest)
            );
            match self
                .transport
                .execute(
                    &host.ssh,
                    &trusted.public_key_base64,
                    passphrase.as_ref(),
                    &command,
                    &cancellation,
                )
                .await
            {
                Err(error) => {
                    let mut failure = update_error(
                        "The server helper repair outcome could not be confirmed. Refresh / Reconnect to check the installed helper before retrying.",
                    );
                    failure.remote_state_changed = true;
                    failure.technical_detail = Some(error.to_string());
                    Err(failure)
                }
                Ok(reply) => {
                    if reply.exit_status == 0
                        && matches!(
                            reply.stdout.as_slice(),
                            b"helper_updated\n" | b"helper_already_current\n"
                        )
                    {
                        Ok(())
                    } else {
                        // Only the fixed installer and bundled executable run here; no credentials.
                        let detail = String::from_utf8_lossy(&reply.stderr);
                        let mut error = update_error(
                            "Automatic server helper repair failed. The previous helper is retained unless a rollback failure is reported below.",
                        );
                        error.technical_detail = Some(detail.chars().take(2000).collect());
                        Err(error)
                    }
                }
            }
        };
        // Also cleans up uploads when sudo was refused. No broad or server-controlled path.
        let cleanup = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                &format!("rm -rf -- {}", shell_quote(&path)),
                &CancellationToken::new(),
            )
            .await;
        let cleanup_failed = !cleanup.as_ref().is_ok_and(|r| r.exit_status == 0);
        if let Err(mut error) = result {
            if cleanup_failed {
                let detail = error.technical_detail.get_or_insert_with(String::new);
                detail.push_str(&format!("\nStaging cleanup could not be confirmed: {path}"));
            }
            return Err(error);
        }
        if cleanup_failed {
            let mut error = update_error(
                "Helper repair completed, but staging cleanup could not be confirmed. Reconnect to verify the helper.",
            );
            error.technical_detail = Some(format!("Unconfirmed staging directory: {path}"));
            return Err(error);
        }
        let after = self.remote_identity(host_id).await?;
        if after.appliance_id != before.appliance_id
            || after.machine_fingerprint != before.machine_fingerprint
            || !REQUIRED
                .iter()
                .all(|r| after.capabilities.iter().any(|c| c == r))
        {
            return Err(update_error(
                "The repaired helper did not confirm the original appliance identity and required capabilities. Reconnect after inspecting the server.",
            ));
        }
        Ok(())
    }
}

fn valid_stage(path: &str) -> bool {
    path.strip_prefix("/tmp/vpnctl-helper.")
        .is_some_and(|suffix| {
            suffix.len() == 10 && suffix.bytes().all(|c| c.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_paths_cannot_escape_or_inject_shell() {
        assert!(valid_stage("/tmp/vpnctl-helper.ab12CD34ef"));
        for path in [
            "/tmp",
            "/tmp/vpnctl-helper.../../../",
            "/tmp/vpnctl-helper.ab12CD34e;",
            "/tmp/vpnctl-helper.ab12CD34ef\n",
        ] {
            assert!(!valid_stage(path));
        }
    }

    #[test]
    fn rejects_wrong_elf_architecture_and_non_executable_payloads() {
        assert!(!payload_valid(&HelperPayload {
            architecture: "x86_64",
            contents: b"script"
        }));
        let mut elf = [0u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18] = 62;
        let contents = Box::leak(Box::new(elf));
        assert!(payload_valid(&HelperPayload {
            architecture: "x86_64",
            contents
        }));
        assert!(!payload_valid(&HelperPayload {
            architecture: "aarch64",
            contents
        }));
    }
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use vam_authority::manifest::{Operation, Reply, Response};
    use vam_authority_client::{AuthorityClientError, AuthoritySshSession, ManifestExchange};
    use vam_core::SshConnectionConfig;
    use vam_ssh::{CommandResult, DownloadRequest, SshError, SshTransport};
    use zeroize::Zeroizing;

    struct Server {
        appliance: Uuid,
        current: AtomicBool,
        fail_install: AtomicBool,
        fail_cleanup: AtomicBool,
        lose_reply: AtomicBool,
        changed_identity: AtomicBool,
        installs: AtomicUsize,
        uploads: AtomicUsize,
    }
    #[async_trait]
    impl ManifestExchange for Server {
        async fn exchange_manifest(
            &self,
            _: &AuthoritySshSession<'_>,
            request: &vam_authority::manifest::Request,
            _: &CancellationToken,
        ) -> Result<Response, AuthorityClientError> {
            assert!(matches!(request.operation, Operation::Info));
            Ok(Response {
                compatibility: vam_authority::manifest::Compatibility::default(),
                request_id: request.request_id,
                result: Ok(Reply::Info {
                    appliance_id: self.appliance,
                    machine_fingerprint: if self.changed_identity.load(Ordering::SeqCst) {
                        "changed"
                    } else {
                        "original"
                    }
                    .into(),
                    software_version: "0.1.0".into(),
                    capabilities: if self.current.load(Ordering::SeqCst) {
                        REQUIRED.iter().map(|c| (*c).into()).collect()
                    } else {
                        vec![]
                    },
                }),
            })
        }
    }
    #[async_trait]
    impl SshTransport for Server {
        async fn probe_host_key(
            &self,
            _: &SshConnectionConfig,
            _: &CancellationToken,
        ) -> Result<vam_protocol::HostKeyInfo, SshError> {
            unreachable!()
        }
        async fn execute(
            &self,
            _: &SshConnectionConfig,
            trusted: &str,
            _: Option<&Zeroizing<String>>,
            command: &str,
            _: &CancellationToken,
        ) -> Result<CommandResult, SshError> {
            assert_eq!(trusted, "approved-key");
            let mut result = CommandResult {
                stdout: vec![],
                stderr: vec![],
                exit_status: 0,
            };
            if command.starts_with("uname") {
                result.stdout = b"Linux\nx86_64\n".to_vec();
            } else if command.starts_with("umask") {
                result.stdout = b"/tmp/vpnctl-helper.ab12CD34ef\n".to_vec();
            } else if command.contains("sha256sum /usr/local/libexec/vam-server") {
                result.stdout =
                    format!("{}  /usr/local/libexec/vam-server\n", "0".repeat(64)).into_bytes();
            } else if command.starts_with("/usr/bin/sudo") {
                assert!(command.contains("flock -w 40"));
                self.installs.fetch_add(1, Ordering::SeqCst);
                if self.fail_install.load(Ordering::SeqCst) {
                    result.exit_status = 1;
                    result.stderr = b"sudo: a password is required".to_vec();
                } else {
                    self.current.store(true, Ordering::SeqCst);
                    if self.lose_reply.swap(false, Ordering::SeqCst) {
                        return Err(SshError::Timeout);
                    }
                    result.stdout = b"helper_updated\n".to_vec();
                }
            } else {
                assert!(command.starts_with("rm -rf -- '/tmp/vpnctl-helper."));
                if self.fail_cleanup.load(Ordering::SeqCst) {
                    result.exit_status = 1;
                }
            }
            Ok(result)
        }
        async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError> {
            assert_eq!(request.mode, 0o600);
            self.uploads.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn download(&self, _: DownloadRequest<'_>) -> Result<Zeroizing<Vec<u8>>, SshError> {
            unreachable!()
        }
    }
    async fn service() -> (ApplicationService, Arc<Server>, Uuid) {
        let server = Arc::new(Server {
            appliance: Uuid::new_v4(),
            current: AtomicBool::new(false),
            fail_install: AtomicBool::new(false),
            fail_cleanup: AtomicBool::new(false),
            lose_reply: AtomicBool::new(false),
            changed_identity: AtomicBool::new(false),
            installs: AtomicUsize::new(0),
            uploads: AtomicUsize::new(0),
        });
        let mut elf = [0u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18] = 62;
        let service = ApplicationService::with_transport(
            vam_storage::Storage::in_memory().await.unwrap(),
            Arc::new(vam_secrets::MemorySecretStore::default()),
            server.clone(),
        )
        .with_manifest_exchange(server.clone())
        .with_helper_payloads(vec![HelperPayload {
            architecture: "x86_64",
            contents: Box::leak(Box::new(elf)),
        }]);
        let host = service
            .create_host(super::super::CreateHostInput {
                display_name: "test".into(),
                hostname: "server".into(),
                port: 22,
                username: "test".into(),
                private_key_path: "/unused".into(),
                passphrase: None,
            })
            .await
            .unwrap();
        service
            .storage
            .approve_host_key(
                host.id,
                &vam_protocol::HostKeyInfo {
                    hostname: "server".into(),
                    resolved_address: "127.0.0.1".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    sha256_fingerprint: "SHA256:approved".into(),
                    public_key_base64: "approved-key".into(),
                },
                false,
            )
            .await
            .unwrap();
        (service, server, host.id)
    }
    #[tokio::test]
    async fn repair_is_automatic_and_single_flight_and_preserves_identity() {
        let (service, server, host) = service().await;
        let (a, b) = tokio::join!(
            service.ensure_remote_helper(host),
            service.ensure_remote_helper(host)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(server.installs.load(Ordering::SeqCst), 1);
        assert_eq!(server.uploads.load(Ordering::SeqCst), 1);
        assert_eq!(
            service.remote_identity(host).await.unwrap().appliance_id,
            server.appliance
        );
    }
    #[tokio::test]
    async fn current_helper_is_never_overwritten() {
        let (service, server, host) = service().await;
        server.current.store(true, Ordering::SeqCst);
        service.ensure_remote_helper(host).await.unwrap();
        assert_eq!(server.installs.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn failed_install_is_visible_and_reconnect_retries() {
        let (service, server, host) = service().await;
        server.fail_install.store(true, Ordering::SeqCst);
        assert_eq!(
            service.ensure_remote_helper(host).await.unwrap_err().code,
            "helper_update_failed"
        );
        assert!(!server.current.load(Ordering::SeqCst));
        server.fail_install.store(false, Ordering::SeqCst);
        service.ensure_remote_helper(host).await.unwrap();
    }
    #[tokio::test]
    async fn lost_success_reply_is_reconciled_without_reinstalling() {
        let (service, server, host) = service().await;
        server.lose_reply.store(true, Ordering::SeqCst);
        assert!(service.ensure_remote_helper(host).await.is_err());
        service.ensure_remote_helper(host).await.unwrap();
        assert_eq!(server.installs.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn identity_change_blocks_upload_and_installation() {
        let (service, server, host) = service().await;
        service.remote_identity(host).await.unwrap();
        server.changed_identity.store(true, Ordering::SeqCst);
        assert!(service.ensure_remote_helper(host).await.is_err());
        assert_eq!(server.uploads.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn missing_bundle_produces_actionable_error() {
        let (service, server, host) = service().await;
        let service = service.with_helper_payloads(vec![]);
        assert!(
            service
                .ensure_remote_helper(host)
                .await
                .unwrap_err()
                .message
                .contains("bundled")
        );
        assert_eq!(server.installs.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn cleanup_failure_is_reported_alongside_the_original_install_failure() {
        let (service, server, host) = service().await;
        server.fail_install.store(true, Ordering::SeqCst);
        server.fail_cleanup.store(true, Ordering::SeqCst);
        let error = service.ensure_remote_helper(host).await.unwrap_err();
        assert_eq!(error.code, "helper_update_failed");
        let detail = error.technical_detail.unwrap();
        assert!(detail.contains("sudo: a password is required"));
        assert!(detail.contains("Staging cleanup could not be confirmed"));
    }
}
