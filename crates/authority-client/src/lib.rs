use std::sync::Arc;

use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_authority::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRequestEnvelope, AuthorityResponseEnvelope,
};
use vam_core::SshConnectionConfig;
use vam_ssh::{DownloadRequest, SshError, SshTransport, UploadRequest};
use zeroize::Zeroizing;

const HELPER: &str = "/usr/local/libexec/vam-server";
const SUDO: &str = "/usr/bin/sudo -n --";
const EXCHANGE_ROOT: &str = "/var/lib/vpn-appliance-manager/exchange";
pub const MAX_AUTHORITY_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum AuthorityClientError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error("the appliance helper command failed with exit status {status}")]
    HelperCommand { status: u32 },
    #[error("the appliance helper returned an invalid nonsecret status marker")]
    InvalidStatus,
    #[error("the authority request exceeds the {max_bytes}-byte limit")]
    RequestTooLarge { max_bytes: usize },
    #[error("the appliance returned invalid authority JSON")]
    InvalidResponse(#[from] serde_json::Error),
    #[error("the appliance response does not match the request")]
    ResponseMismatch,
    #[error("the authority exchange completed but protected-file cleanup failed: {0}")]
    Cleanup(Box<AuthorityClientError>),
}

pub struct AuthoritySshSession<'a> {
    pub config: &'a SshConnectionConfig,
    pub trusted_key_base64: &'a str,
    pub passphrase: Option<&'a Zeroizing<String>>,
}

#[derive(Clone)]
pub struct AuthorityClient {
    transport: Arc<dyn SshTransport>,
}

impl AuthorityClient {
    #[must_use]
    pub fn new(transport: Arc<dyn SshTransport>) -> Self {
        Self { transport }
    }

    pub async fn exchange(
        &self,
        session: &AuthoritySshSession<'_>,
        request: &AuthorityRequestEnvelope,
        cancellation: &CancellationToken,
    ) -> Result<AuthorityResponseEnvelope, AuthorityClientError> {
        request
            .validate_protocol()
            .map_err(|_| AuthorityClientError::ResponseMismatch)?;
        let request_bytes = Zeroizing::new(serde_json::to_vec(request)?);
        if request_bytes.len() > MAX_AUTHORITY_MESSAGE_BYTES {
            return Err(AuthorityClientError::RequestTooLarge {
                max_bytes: MAX_AUTHORITY_MESSAGE_BYTES,
            });
        }

        let uid = self.prepare(session, cancellation).await?;
        let request_path = exchange_path(uid, "requests", request.request_id);
        let response_path = exchange_path(uid, "responses", request.request_id);
        let result = async {
            self.transport
                .upload(UploadRequest {
                    config: session.config,
                    trusted_key_base64: session.trusted_key_base64,
                    passphrase: session.passphrase,
                    remote_path: &request_path,
                    contents: &request_bytes,
                    mode: 0o600,
                    cancellation,
                })
                .await?;
            self.run_rpc_and_download(session, request.request_id, &response_path, cancellation)
                .await
        }
        .await;
        let cleanup_cancellation = CancellationToken::new();
        let cleanup = self
            .execute_helper(
                session,
                &format!("cleanup {}", request.request_id),
                &cleanup_cancellation,
            )
            .await;
        if let Err(error) = cleanup {
            return Err(AuthorityClientError::Cleanup(Box::new(error)));
        }
        result
    }

    async fn prepare(
        &self,
        session: &AuthoritySshSession<'_>,
        cancellation: &CancellationToken,
    ) -> Result<u32, AuthorityClientError> {
        let output = self
            .execute_helper(session, "prepare", cancellation)
            .await?;
        let marker = output
            .strip_prefix("exchange_uid=")
            .ok_or(AuthorityClientError::InvalidStatus)?;
        marker
            .parse()
            .map_err(|_| AuthorityClientError::InvalidStatus)
    }

    async fn run_rpc_and_download(
        &self,
        session: &AuthoritySshSession<'_>,
        request_id: Uuid,
        response_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<AuthorityResponseEnvelope, AuthorityClientError> {
        let output = self
            .execute_helper(session, &format!("rpc {request_id}"), cancellation)
            .await?;
        if output != format!("response_ready={request_id}") {
            return Err(AuthorityClientError::InvalidStatus);
        }
        let response_bytes = self
            .transport
            .download(DownloadRequest {
                config: session.config,
                trusted_key_base64: session.trusted_key_base64,
                passphrase: session.passphrase,
                remote_path: response_path,
                max_bytes: MAX_AUTHORITY_MESSAGE_BYTES,
                cancellation,
            })
            .await?;
        let response: AuthorityResponseEnvelope = serde_json::from_slice(&response_bytes)?;
        if response.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || response.request_id != request_id
        {
            return Err(AuthorityClientError::ResponseMismatch);
        }
        Ok(response)
    }

    async fn execute_helper(
        &self,
        session: &AuthoritySshSession<'_>,
        arguments: &str,
        cancellation: &CancellationToken,
    ) -> Result<String, AuthorityClientError> {
        let command = format!("{SUDO} {HELPER} {arguments}");
        let result = self
            .transport
            .execute(
                session.config,
                session.trusted_key_base64,
                session.passphrase,
                &command,
                cancellation,
            )
            .await?;
        if result.exit_status != 0 {
            return Err(AuthorityClientError::HelperCommand {
                status: result.exit_status,
            });
        }
        let stdout = result.stdout_text()?;
        Ok(stdout.trim().to_owned())
    }
}

fn exchange_path(uid: u32, leaf: &str, request_id: Uuid) -> String {
    format!("{EXCHANGE_ROOT}/{uid}/{leaf}/{request_id}.json")
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use vam_authority::{AuthorityInfo, AuthorityOperation, AuthorityResponse};
    use vam_protocol::HostKeyInfo;
    use vam_ssh::CommandResult;

    use super::*;

    #[derive(Default)]
    struct MockState {
        commands: Vec<String>,
        uploads: Vec<(String, Vec<u8>, u32, String)>,
        downloads: Vec<String>,
        response: Vec<u8>,
        fail_upload: bool,
    }

    #[derive(Default)]
    struct MockTransport {
        state: Mutex<MockState>,
    }

    #[async_trait]
    impl SshTransport for MockTransport {
        async fn probe_host_key(
            &self,
            _config: &SshConnectionConfig,
            _cancellation: &CancellationToken,
        ) -> Result<HostKeyInfo, SshError> {
            unreachable!("authority exchange never probes or accepts a host key")
        }

        async fn execute(
            &self,
            _config: &SshConnectionConfig,
            trusted_key_base64: &str,
            _passphrase: Option<&Zeroizing<String>>,
            command: &str,
            _cancellation: &CancellationToken,
        ) -> Result<CommandResult, SshError> {
            assert_eq!(trusted_key_base64, "locally-approved-key");
            self.state.lock().unwrap().commands.push(command.into());
            let stdout = if command.ends_with(" prepare") {
                b"exchange_uid=1001\n".to_vec()
            } else if command.contains(" rpc ") {
                let request_id = command.split_whitespace().last().unwrap();
                format!("response_ready={request_id}\n").into_bytes()
            } else if command.contains(" cleanup ") {
                let request_id = command.split_whitespace().last().unwrap();
                format!("exchange_removed={request_id}\n").into_bytes()
            } else {
                unreachable!("unexpected helper command")
            };
            Ok(CommandResult {
                stdout,
                stderr: Vec::new(),
                exit_status: 0,
            })
        }

        async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError> {
            let mut state = self.state.lock().unwrap();
            state.uploads.push((
                request.remote_path.into(),
                request.contents.into(),
                request.mode,
                request.trusted_key_base64.into(),
            ));
            if state.fail_upload {
                return Err(SshError::Sftp("simulated upload failure".into()));
            }
            Ok(())
        }

        async fn download(
            &self,
            request: DownloadRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, SshError> {
            let mut state = self.state.lock().unwrap();
            state.downloads.push(request.remote_path.into());
            Ok(Zeroizing::new(state.response.clone()))
        }
    }

    fn config() -> SshConnectionConfig {
        SshConnectionConfig {
            hostname: "vpn.example.test".into(),
            port: 22,
            username: "operator".into(),
            private_key_path: PathBuf::from("operator-key"),
            passphrase_ref: None,
        }
    }

    fn info_request(request_id: Uuid) -> AuthorityRequestEnvelope {
        AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id,
            appliance_id: None,
            operation: AuthorityOperation::Info,
        }
    }

    fn info_response(request_id: Uuid, appliance_id: Uuid) -> AuthorityResponseEnvelope {
        AuthorityResponseEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id,
            result: Ok(AuthorityResponse::Info(AuthorityInfo {
                appliance_id,
                revision: 0,
                protocol_version: AUTHORITY_PROTOCOL_VERSION,
                schema_version: vam_authority::AUTHORITY_SCHEMA_VERSION,
                software_version: "test".into(),
            })),
        }
    }

    #[tokio::test]
    async fn exchange_uses_only_fixed_commands_verified_ssh_and_bounded_files() {
        let request_id = Uuid::new_v4();
        let transport = Arc::new(MockTransport::default());
        transport.state.lock().unwrap().response =
            serde_json::to_vec(&info_response(request_id, Uuid::new_v4())).unwrap();
        let client = AuthorityClient::new(transport.clone());
        let config = config();
        let session = AuthoritySshSession {
            config: &config,
            trusted_key_base64: "locally-approved-key",
            passphrase: None,
        };
        let response = client
            .exchange(
                &session,
                &info_request(request_id),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.request_id, request_id);

        let state = transport.state.lock().unwrap();
        assert_eq!(
            state.commands,
            vec![
                format!("{SUDO} {HELPER} prepare"),
                format!("{SUDO} {HELPER} rpc {request_id}"),
                format!("{SUDO} {HELPER} cleanup {request_id}"),
            ]
        );
        assert_eq!(state.uploads.len(), 1);
        assert_eq!(
            state.uploads[0].0,
            exchange_path(1001, "requests", request_id)
        );
        assert_eq!(state.uploads[0].2, 0o600);
        assert_eq!(state.uploads[0].3, "locally-approved-key");
        assert_eq!(
            state.downloads,
            vec![exchange_path(1001, "responses", request_id)]
        );
    }

    #[tokio::test]
    async fn invalid_response_is_rejected_and_always_cleaned_up() {
        let request_id = Uuid::new_v4();
        let transport = Arc::new(MockTransport::default());
        transport.state.lock().unwrap().response = b"not-json".to_vec();
        let client = AuthorityClient::new(transport.clone());
        let config = config();
        let result = client
            .exchange(
                &AuthoritySshSession {
                    config: &config,
                    trusted_key_base64: "locally-approved-key",
                    passphrase: None,
                },
                &info_request(request_id),
                &CancellationToken::new(),
            )
            .await;
        assert!(matches!(
            result,
            Err(AuthorityClientError::InvalidResponse(_))
        ));
        assert_eq!(
            transport.state.lock().unwrap().commands.last().unwrap(),
            &format!("{SUDO} {HELPER} cleanup {request_id}")
        );
    }

    #[tokio::test]
    async fn partial_upload_failure_still_attempts_uncancelled_cleanup() {
        let request_id = Uuid::new_v4();
        let transport = Arc::new(MockTransport::default());
        transport.state.lock().unwrap().fail_upload = true;
        let client = AuthorityClient::new(transport.clone());
        let config = config();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = client
            .exchange(
                &AuthoritySshSession {
                    config: &config,
                    trusted_key_base64: "locally-approved-key",
                    passphrase: None,
                },
                &info_request(request_id),
                &cancellation,
            )
            .await;
        assert!(matches!(result, Err(AuthorityClientError::Ssh(_))));
        assert_eq!(
            transport.state.lock().unwrap().commands.last().unwrap(),
            &format!("{SUDO} {HELPER} cleanup {request_id}")
        );
    }
}
