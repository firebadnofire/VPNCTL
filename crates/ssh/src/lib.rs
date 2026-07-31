use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use russh::{
    ChannelMsg, Disconnect, client,
    keys::{PrivateKeyWithHashAlg, PublicKeyBase64, load_secret_key, ssh_key},
};
use russh_sftp::{
    client::SftpSession,
    protocol::{FileAttributes, OpenFlags},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::lookup_host,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use vam_core::SshConnectionConfig;
use vam_protocol::HostKeyInfo;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
}

pub struct UploadRequest<'a> {
    pub config: &'a SshConnectionConfig,
    pub trusted_key_base64: &'a str,
    pub passphrase: Option<&'a Zeroizing<String>>,
    pub remote_path: &'a str,
    pub contents: &'a [u8],
    pub mode: u32,
    pub cancellation: &'a CancellationToken,
}

pub struct DownloadRequest<'a> {
    pub config: &'a SshConnectionConfig,
    pub trusted_key_base64: &'a str,
    pub passphrase: Option<&'a Zeroizing<String>>,
    pub remote_path: &'a str,
    pub max_bytes: usize,
    pub cancellation: &'a CancellationToken,
}

impl CommandResult {
    pub fn stdout_text(&self) -> Result<String, SshError> {
        String::from_utf8(self.stdout.clone()).map_err(|_| SshError::NonUtf8)
    }
}

#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH host key is not trusted")]
    HostKeyUntrusted,
    #[error("SSH host key changed")]
    HostKeyChanged,
    #[error("SSH authentication failed")]
    Authentication,
    #[error("SSH operation timed out")]
    Timeout,
    #[error("SSH operation was cancelled")]
    Cancelled,
    #[error("SSH output was not UTF-8")]
    NonUtf8,
    #[error("SSH protocol error: {0}")]
    Protocol(String),
    #[error("SFTP error: {0}")]
    Sftp(String),
    #[error("remote file exceeds the {max_bytes}-byte download limit")]
    DownloadTooLarge { max_bytes: usize },
    #[error("SSH key file could not be loaded: {0}")]
    KeyFile(String),
    #[error("SSH command did not report an exit status")]
    MissingExitStatus,
}

#[async_trait]
pub trait SshTransport: Send + Sync {
    async fn probe_host_key(
        &self,
        config: &SshConnectionConfig,
        cancellation: &CancellationToken,
    ) -> Result<HostKeyInfo, SshError>;

    async fn execute(
        &self,
        config: &SshConnectionConfig,
        trusted_key_base64: &str,
        passphrase: Option<&Zeroizing<String>>,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<CommandResult, SshError>;

    async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError>;
    async fn download(&self, request: DownloadRequest<'_>) -> Result<Zeroizing<Vec<u8>>, SshError>;
}

#[derive(Debug)]
pub struct RusshTransport {
    connect_timeout: Duration,
    operation_timeout: Duration,
}

impl Default for RusshTransport {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            operation_timeout: Duration::from_mins(1),
        }
    }
}

impl RusshTransport {
    #[must_use]
    pub const fn with_timeouts(connect_timeout: Duration, operation_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            operation_timeout,
        }
    }

    async fn connect(
        &self,
        config: &SshConnectionConfig,
        verification: Verification,
        cancellation: &CancellationToken,
    ) -> Result<client::Handle<Verifier>, SshError> {
        let client_config = Arc::new(client::Config {
            inactivity_timeout: Some(self.operation_timeout),
            ..client::Config::default()
        });
        let address = (config.hostname.as_str(), config.port);
        guarded(
            cancellation,
            self.connect_timeout,
            client::connect(client_config, address, Verifier { verification }),
        )
        .await
        .map_err(map_russh)
    }

    async fn authenticated(
        &self,
        config: &SshConnectionConfig,
        trusted_key_base64: &str,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<client::Handle<Verifier>, SshError> {
        let mut handle = self
            .connect(
                config,
                Verification::Expected(trusted_key_base64.to_owned()),
                cancellation,
            )
            .await?;
        let key = load_secret_key(
            &config.private_key_path,
            passphrase.map(|value| value.as_str()),
        )
        .map_err(|error| SshError::KeyFile(error.to_string()))?;
        let hash = guarded(
            cancellation,
            self.connect_timeout,
            handle.best_supported_rsa_hash(),
        )
        .await
        .map_err(map_russh)?
        .flatten();
        let result = guarded(
            cancellation,
            self.connect_timeout,
            handle.authenticate_publickey(
                config.username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            ),
        )
        .await
        .map_err(map_russh)?;
        if !result.success() {
            return Err(SshError::Authentication);
        }
        Ok(handle)
    }
}

#[derive(Clone)]
enum Verification {
    Probe(Arc<Mutex<Option<ssh_key::PublicKey>>>),
    Expected(String),
}

struct Verifier {
    verification: Verification,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.verification {
            Verification::Probe(slot) => {
                if let Ok(mut slot) = slot.lock() {
                    *slot = Some(server_public_key.clone());
                }
                Ok(true)
            }
            Verification::Expected(expected) => {
                Ok(server_public_key.public_key_base64() == *expected)
            }
        }
    }
}

async fn guarded<T, E>(
    cancellation: &CancellationToken,
    duration: Duration,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, GuardError<E>> {
    tokio::select! {
        () = cancellation.cancelled() => Err(GuardError::Cancelled),
        result = timeout(duration, operation) => {
            result.map_err(|_| GuardError::Timeout)?.map_err(GuardError::Inner)
        }
    }
}

enum GuardError<E> {
    Cancelled,
    Timeout,
    Inner(E),
}

fn map_russh(error: GuardError<russh::Error>) -> SshError {
    match error {
        GuardError::Cancelled => SshError::Cancelled,
        GuardError::Timeout => SshError::Timeout,
        GuardError::Inner(russh::Error::UnknownKey) => SshError::HostKeyChanged,
        GuardError::Inner(error) => SshError::Protocol(error.to_string()),
    }
}

fn map_sftp<E: std::fmt::Display>(error: GuardError<E>) -> SshError {
    match error {
        GuardError::Cancelled => SshError::Cancelled,
        GuardError::Timeout => SshError::Timeout,
        GuardError::Inner(error) => SshError::Sftp(error.to_string()),
    }
}

fn file_attributes(mode: u32) -> FileAttributes {
    FileAttributes {
        permissions: Some(mode),
        ..FileAttributes::empty()
    }
}

async fn read_bounded(
    reader: &mut (impl AsyncRead + Unpin),
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SshError> {
    let mut contents = Zeroizing::new(Vec::with_capacity(max_bytes.min(16 * 1024)));
    let mut buffer = Zeroizing::new(vec![0_u8; 16 * 1024]);
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|error| SshError::Sftp(error.to_string()))?;
        if count == 0 {
            return Ok(contents);
        }
        if contents.len().saturating_add(count) > max_bytes {
            return Err(SshError::DownloadTooLarge { max_bytes });
        }
        contents.extend_from_slice(&buffer[..count]);
    }
}

#[async_trait]
impl SshTransport for RusshTransport {
    async fn probe_host_key(
        &self,
        config: &SshConnectionConfig,
        cancellation: &CancellationToken,
    ) -> Result<HostKeyInfo, SshError> {
        let slot = Arc::new(Mutex::new(None));
        let handle = self
            .connect(config, Verification::Probe(Arc::clone(&slot)), cancellation)
            .await?;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "host-key probe complete", "en")
            .await;
        let key = slot
            .lock()
            .map_err(|_| SshError::Protocol("host-key probe lock was poisoned".into()))?
            .clone()
            .ok_or_else(|| SshError::Protocol("server supplied no host key".into()))?;
        let resolved_address = guarded(cancellation, self.connect_timeout, async {
            let mut addresses = lookup_host((config.hostname.as_str(), config.port)).await?;
            addresses.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved")
            })
        })
        .await
        .map_err(|error| match error {
            GuardError::Cancelled => SshError::Cancelled,
            GuardError::Timeout => SshError::Timeout,
            GuardError::Inner(error) => SshError::Protocol(error.to_string()),
        })?
        .ip()
        .to_string();
        Ok(HostKeyInfo {
            hostname: config.hostname.clone(),
            resolved_address,
            port: config.port,
            algorithm: key.algorithm().as_str().to_owned(),
            sha256_fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            public_key_base64: key.public_key_base64(),
        })
    }

    async fn execute(
        &self,
        config: &SshConnectionConfig,
        trusted_key_base64: &str,
        passphrase: Option<&Zeroizing<String>>,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<CommandResult, SshError> {
        let handle = self
            .authenticated(config, trusted_key_base64, passphrase, cancellation)
            .await?;
        let mut channel = guarded(
            cancellation,
            self.operation_timeout,
            handle.channel_open_session(),
        )
        .await
        .map_err(map_russh)?;
        guarded(
            cancellation,
            self.operation_timeout,
            channel.exec(true, command),
        )
        .await
        .map_err(map_russh)?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        loop {
            let message = tokio::select! {
                () = cancellation.cancelled() => return Err(SshError::Cancelled),
                () = sleep(self.operation_timeout) => return Err(SshError::Timeout),
                message = channel.wait() => message,
            };
            let Some(message) = message else {
                break;
            };
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                _ => {}
            }
        }
        let _ = handle
            .disconnect(Disconnect::ByApplication, "command complete", "en")
            .await;
        Ok(CommandResult {
            stdout,
            stderr,
            exit_status: exit_status.ok_or(SshError::MissingExitStatus)?,
        })
    }

    async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError> {
        let handle = self
            .authenticated(
                request.config,
                request.trusted_key_base64,
                request.passphrase,
                request.cancellation,
            )
            .await?;
        let channel = guarded(
            request.cancellation,
            self.operation_timeout,
            handle.channel_open_session(),
        )
        .await
        .map_err(map_russh)?;
        guarded(
            request.cancellation,
            self.operation_timeout,
            channel.request_subsystem(true, "sftp"),
        )
        .await
        .map_err(map_russh)?;
        let sftp = guarded(
            request.cancellation,
            self.operation_timeout,
            SftpSession::new(channel.into_stream()),
        )
        .await
        .map_err(map_sftp)?;
        let mut file = guarded(
            request.cancellation,
            self.operation_timeout,
            sftp.open_with_flags_and_attributes(
                request.remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                file_attributes(request.mode),
            ),
        )
        .await
        .map_err(map_sftp)?;
        guarded(
            request.cancellation,
            self.operation_timeout,
            file.write_all(request.contents),
        )
        .await
        .map_err(map_sftp)?;
        guarded(
            request.cancellation,
            self.operation_timeout,
            file.shutdown(),
        )
        .await
        .map_err(map_sftp)?;
        guarded(
            request.cancellation,
            self.operation_timeout,
            sftp.set_metadata(request.remote_path, file_attributes(request.mode)),
        )
        .await
        .map_err(map_sftp)?;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "upload complete", "en")
            .await;
        Ok(())
    }

    async fn download(&self, request: DownloadRequest<'_>) -> Result<Zeroizing<Vec<u8>>, SshError> {
        let handle = self
            .authenticated(
                request.config,
                request.trusted_key_base64,
                request.passphrase,
                request.cancellation,
            )
            .await?;
        let channel = guarded(
            request.cancellation,
            self.operation_timeout,
            handle.channel_open_session(),
        )
        .await
        .map_err(map_russh)?;
        guarded(
            request.cancellation,
            self.operation_timeout,
            channel.request_subsystem(true, "sftp"),
        )
        .await
        .map_err(map_russh)?;
        let sftp = guarded(
            request.cancellation,
            self.operation_timeout,
            SftpSession::new(channel.into_stream()),
        )
        .await
        .map_err(map_sftp)?;
        let mut file = guarded(
            request.cancellation,
            self.operation_timeout,
            sftp.open(request.remote_path),
        )
        .await
        .map_err(map_sftp)?;
        let contents = guarded(
            request.cancellation,
            self.operation_timeout,
            read_bounded(&mut file, request.max_bytes),
        )
        .await
        .map_err(|error| match error {
            GuardError::Cancelled => SshError::Cancelled,
            GuardError::Timeout => SshError::Timeout,
            GuardError::Inner(error) => error,
        })?;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "download complete", "en")
            .await;
        Ok(contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    const ED25519_PPK: &str = r"PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: user@example.com
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XF
Sqti
Private-Lines: 1
AAAAILYGwiLRDBba4WxwpNRRc0cuxhfgXGVpINJuVsCPtZHt
Private-MAC: 94140d0344fad6aa1bf7b71e9c93db11ccac8a232f8a51e11c024869d608c82d
";

    #[tokio::test]
    async fn cancellation_interrupts_a_guarded_operation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result: Result<(), GuardError<std::convert::Infallible>> = guarded(
            &cancellation,
            Duration::from_secs(1),
            std::future::pending(),
        )
        .await;
        assert!(matches!(result, Err(GuardError::Cancelled)));
    }

    #[tokio::test]
    async fn bounded_download_accepts_limit_and_rejects_oversize_input() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"certificate").await.unwrap();
        });
        let contents = read_bounded(&mut reader, 11).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(contents.as_slice(), b"certificate");

        let (mut writer, mut reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"certificate").await.unwrap();
        });
        assert!(matches!(
            read_bounded(&mut reader, 10).await,
            Err(SshError::DownloadTooLarge { max_bytes: 10 })
        ));
        writer_task.await.unwrap();
    }

    #[test]
    fn upload_attributes_never_request_truncation_or_chown() {
        let attributes = file_attributes(0o600);
        assert_eq!(attributes.permissions, Some(0o600));
        assert_eq!(attributes.size, None);
        assert_eq!(attributes.uid, None);
        assert_eq!(attributes.gid, None);
        assert_eq!(attributes.atime, None);
        assert_eq!(attributes.mtime, None);
    }

    #[test]
    fn putty_ppk_private_keys_load_for_authentication() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("vam-ssh-{}-{suffix}.ppk", std::process::id()));
        fs::write(&path, ED25519_PPK).expect("test key can be written");

        let key = load_secret_key(&path, None).expect("ppk key should load");
        fs::remove_file(path).expect("test key can be removed");

        assert_eq!(key.algorithm().as_str(), "ssh-ed25519");
    }
}
