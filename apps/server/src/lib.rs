use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use thiserror::Error;
use uuid::Uuid;
use vam_authority::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityError, AuthorityFailure, AuthorityFailureCode,
    AuthorityOperation, AuthorityRequestEnvelope, AuthorityResponse, AuthorityResponseEnvelope,
    AuthorityStore,
};

pub const MANAGEMENT_ROOT: &str = "/var/lib/vpn-appliance-manager";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const APPLIANCE_ID_MAX_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("invalid helper invocation: {0}")]
    InvalidInvocation(String),
    #[error("vam-server must run with effective root privileges")]
    Privileges,
    #[error("caller identity is unavailable or invalid")]
    CallerIdentity,
    #[error("request file is missing, unsafe, or has invalid permissions")]
    UnsafeRequest,
    #[error("request exceeds the {max_bytes}-byte limit")]
    RequestTooLarge { max_bytes: usize },
    #[error("response exceeds the {max_bytes}-byte limit")]
    ResponseTooLarge { max_bytes: usize },
    #[error("managed helper filesystem operation failed: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error("authority response serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl CallerIdentity {
    pub fn from_sudo_environment() -> Result<Self, ServerError> {
        let uid = environment_u32("SUDO_UID")?;
        let gid = environment_u32("SUDO_GID")?;
        Ok(Self { uid, gid })
    }
}

#[derive(Debug, Clone)]
pub struct ServerPaths {
    root: PathBuf,
}

impl ServerPaths {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn control_dir(&self) -> PathBuf {
        self.root.join("control")
    }

    #[must_use]
    pub fn database(&self) -> PathBuf {
        self.control_dir().join("state.sqlite")
    }

    #[must_use]
    pub fn appliance_id(&self) -> PathBuf {
        self.control_dir().join("appliance-id")
    }

    #[must_use]
    pub fn exchange_dir(&self) -> PathBuf {
        self.root.join("exchange")
    }

    #[must_use]
    pub fn caller_exchange_dir(&self, caller: CallerIdentity) -> PathBuf {
        self.exchange_dir().join(caller.uid.to_string())
    }

    #[must_use]
    pub fn requests_dir(&self, caller: CallerIdentity) -> PathBuf {
        self.caller_exchange_dir(caller).join("requests")
    }

    #[must_use]
    pub fn responses_dir(&self, caller: CallerIdentity) -> PathBuf {
        self.caller_exchange_dir(caller).join("responses")
    }

    #[must_use]
    pub fn request(&self, caller: CallerIdentity, request_id: Uuid) -> PathBuf {
        self.requests_dir(caller).join(format!("{request_id}.json"))
    }

    #[must_use]
    pub fn response(&self, caller: CallerIdentity, request_id: Uuid) -> PathBuf {
        self.responses_dir(caller)
            .join(format!("{request_id}.json"))
    }
}

#[derive(Debug, Clone)]
pub struct ServerRuntime {
    paths: ServerPaths,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl ServerRuntime {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            paths: ServerPaths::new(root),
            max_request_bytes: MAX_REQUEST_BYTES,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    #[must_use]
    pub fn with_limits(
        root: impl Into<PathBuf>,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            paths: ServerPaths::new(root),
            max_request_bytes,
            max_response_bytes,
        }
    }

    #[must_use]
    pub const fn paths(&self) -> &ServerPaths {
        &self.paths
    }

    pub fn prepare_exchange(&self, caller: CallerIdentity) -> Result<PathBuf, ServerError> {
        let service = effective_identity();
        create_directory(&self.paths.root, 0o755, service)?;
        create_directory(&self.paths.exchange_dir(), 0o711, service)?;
        create_directory(&self.paths.caller_exchange_dir(caller), 0o711, service)?;
        create_directory(&self.paths.requests_dir(caller), 0o700, caller)?;
        create_directory(&self.paths.responses_dir(caller), 0o711, service)?;
        Ok(self.paths.caller_exchange_dir(caller))
    }

    pub async fn process_request(
        &self,
        caller: CallerIdentity,
        request_id: Uuid,
    ) -> Result<PathBuf, ServerError> {
        self.prepare_exchange(caller)?;
        let request_path = self.paths.request(caller, request_id);
        validate_request_file(&request_path, caller)?;
        let request_bytes = read_bounded(&request_path, self.max_request_bytes)?;
        std::fs::remove_file(&request_path)?;

        let appliance_id = load_or_create_appliance_id(&self.paths)?;
        let store = AuthorityStore::open(&self.paths.database(), appliance_id).await?;
        let response = match serde_json::from_slice::<AuthorityRequestEnvelope>(&request_bytes) {
            Ok(request) => {
                if request.request_id == request_id {
                    dispatch(&store, request).await
                } else {
                    failure_response(
                        request_id,
                        AuthorityFailure {
                            code: AuthorityFailureCode::InvalidRequest,
                            message: "The request identifier does not match its exchange file."
                                .into(),
                            expected_revision: None,
                            current_revision: None,
                            lease_expires_at: None,
                        },
                    )
                }
            }
            Err(_) => failure_response(
                request_id,
                AuthorityFailure {
                    code: AuthorityFailureCode::InvalidRequest,
                    message: "The authority request JSON is invalid.".into(),
                    expected_revision: None,
                    current_revision: None,
                    lease_expires_at: None,
                },
            ),
        };
        let response_bytes = serde_json::to_vec(&response)?;
        if response_bytes.len() > self.max_response_bytes {
            return Err(ServerError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }
        let response_path = self.paths.response(caller, request_id);
        write_response(&response_path, &response_bytes, caller)?;
        Ok(response_path)
    }

    pub fn remove_response(
        &self,
        caller: CallerIdentity,
        request_id: Uuid,
    ) -> Result<(), ServerError> {
        let response_path = self.paths.response(caller, request_id);
        validate_caller_file(&response_path, caller, self.max_response_bytes)?;
        std::fs::remove_file(response_path)?;
        Ok(())
    }
}

pub fn parse_invocation(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Command, ServerError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return Err(ServerError::InvalidInvocation(
            "expected `prepare`, `rpc <request-uuid>`, or `cleanup <request-uuid>`".into(),
        ));
    };
    let command = command
        .into_string()
        .map_err(|_| ServerError::InvalidInvocation("command is not UTF-8".into()))?;
    match command.as_str() {
        "prepare" if arguments.next().is_none() => Ok(Command::Prepare),
        "rpc" | "cleanup" => {
            let request_id = arguments
                .next()
                .ok_or_else(|| {
                    ServerError::InvalidInvocation(format!("{command} requires a request UUID"))
                })?
                .into_string()
                .map_err(|_| ServerError::InvalidInvocation("request UUID is not UTF-8".into()))?;
            if arguments.next().is_some() {
                return Err(ServerError::InvalidInvocation(format!(
                    "{command} accepts exactly one request UUID"
                )));
            }
            let request_id = Uuid::parse_str(&request_id)
                .map_err(|_| ServerError::InvalidInvocation("request UUID is invalid".into()))?;
            Ok(if command == "rpc" {
                Command::Rpc(request_id)
            } else {
                Command::Cleanup(request_id)
            })
        }
        _ => Err(ServerError::InvalidInvocation(
            "expected `prepare`, `rpc <request-uuid>`, or `cleanup <request-uuid>`".into(),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Prepare,
    Rpc(Uuid),
    Cleanup(Uuid),
}

pub fn ensure_privileged() -> Result<(), ServerError> {
    #[cfg(unix)]
    {
        if !nix::unistd::Uid::effective().is_root() {
            return Err(ServerError::Privileges);
        }
    }
    Ok(())
}

async fn dispatch(
    store: &AuthorityStore,
    request: AuthorityRequestEnvelope,
) -> AuthorityResponseEnvelope {
    let request_id = request.request_id;
    let result = dispatch_result(store, request)
        .await
        .map_err(|error| error.failure());
    AuthorityResponseEnvelope {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        request_id,
        result,
    }
}

async fn dispatch_result(
    store: &AuthorityStore,
    request: AuthorityRequestEnvelope,
) -> Result<AuthorityResponse, AuthorityError> {
    request.validate_protocol()?;
    let info = store.info().await?;
    match request.appliance_id {
        Some(expected) if expected != info.appliance_id => {
            return Err(AuthorityError::InvalidState(format!(
                "request targets appliance {expected}, not {}",
                info.appliance_id
            )));
        }
        None if !matches!(request.operation, AuthorityOperation::Info) => {
            return Err(AuthorityError::InvalidState(
                "appliance identity is required for this operation".into(),
            ));
        }
        _ => {}
    }
    match request.operation {
        AuthorityOperation::Info => Ok(AuthorityResponse::Info(info)),
        AuthorityOperation::Snapshot { known_revision } => {
            if known_revision == Some(info.revision) {
                Ok(AuthorityResponse::NotModified(info))
            } else {
                Ok(AuthorityResponse::Snapshot(Box::new(
                    store.snapshot().await?,
                )))
            }
        }
        AuthorityOperation::AcquireLease {
            expected_revision,
            owner,
            scope,
            ttl_seconds,
        } => Ok(AuthorityResponse::Lease(
            store
                .acquire_lease(
                    expected_revision,
                    owner,
                    &scope,
                    Duration::from_secs(ttl_seconds),
                )
                .await?,
        )),
        AuthorityOperation::RenewLease { lease, ttl_seconds } => Ok(AuthorityResponse::Lease(
            store
                .renew_lease(&lease, Duration::from_secs(ttl_seconds))
                .await?,
        )),
        AuthorityOperation::AbortLease { lease } => {
            store.abort_lease(&lease).await?;
            Ok(AuthorityResponse::LeaseAborted)
        }
        AuthorityOperation::Commit { lease, changes } => Ok(AuthorityResponse::Committed(
            store.commit(&lease, &changes).await?,
        )),
        AuthorityOperation::GetSecrets {
            expected_revision,
            ids,
        } => {
            if ids.len() > 4_096 {
                return Err(AuthorityError::InvalidState(
                    "one request may retrieve at most 4096 secrets".into(),
                ));
            }
            Ok(AuthorityResponse::Secrets {
                values: store
                    .get_secrets_at_revision(expected_revision, &ids)
                    .await?,
            })
        }
    }
}

fn failure_response(request_id: Uuid, failure: AuthorityFailure) -> AuthorityResponseEnvelope {
    AuthorityResponseEnvelope {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        request_id,
        result: Err(failure),
    }
}

fn load_or_create_appliance_id(paths: &ServerPaths) -> Result<Uuid, ServerError> {
    let service = effective_identity();
    create_directory(&paths.root, 0o755, service)?;
    create_directory(&paths.control_dir(), 0o700, service)?;
    match read_appliance_id(&paths.appliance_id()) {
        Ok(id) => Ok(id),
        Err(ServerError::Filesystem(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let id = Uuid::new_v4();
            match create_private_file(&paths.appliance_id(), id.to_string().as_bytes()) {
                Ok(()) => Ok(id),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    read_appliance_id(&paths.appliance_id())
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error),
    }
}

fn read_appliance_id(path: &Path) -> Result<Uuid, ServerError> {
    let bytes = read_bounded(path, APPLIANCE_ID_MAX_BYTES)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| {
        ServerError::InvalidInvocation("stored appliance identity is not UTF-8".into())
    })?;
    Uuid::parse_str(value.trim())
        .map_err(|_| ServerError::InvalidInvocation("stored appliance identity is invalid".into()))
}

fn validate_request_file(path: &Path, caller: CallerIdentity) -> Result<(), ServerError> {
    validate_caller_file(path, caller, MAX_REQUEST_BYTES)
}

fn validate_caller_file(
    path: &Path,
    caller: CallerIdentity,
    max_bytes: usize,
) -> Result<(), ServerError> {
    let metadata = std::fs::symlink_metadata(path)?;
    #[cfg(not(unix))]
    let _ = caller;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(max_bytes).map_err(|_| ServerError::UnsafeRequest)?
    {
        return Err(ServerError::UnsafeRequest);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != caller.uid || metadata.mode() & 0o777 != 0o600 {
            return Err(ServerError::UnsafeRequest);
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ServerError> {
    let mut file = File::open(path)?;
    let mut contents = Vec::with_capacity(max_bytes.min(16 * 1024));
    let limit = u64::try_from(max_bytes)
        .map_err(|_| ServerError::RequestTooLarge { max_bytes })?
        .saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut contents)?;
    if contents.len() > max_bytes {
        return Err(ServerError::RequestTooLarge { max_bytes });
    }
    Ok(contents)
}

fn create_private_file(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn write_response(path: &Path, contents: &[u8], caller: CallerIdentity) -> Result<(), ServerError> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    create_private_file(&temporary, contents)?;
    #[cfg(not(unix))]
    let _ = caller;
    #[cfg(unix)]
    if let Err(error) = set_owner(&temporary, caller) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn create_directory(path: &Path, mode: u32, owner: CallerIdentity) -> Result<(), ServerError> {
    let created = match std::fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(ServerError::UnsafeRequest);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let mut metadata = metadata;
        if created {
            set_owner(path, owner)?;
            metadata = std::fs::symlink_metadata(path)?;
        }
        if metadata.uid() != owner.uid {
            return Err(ServerError::UnsafeRequest);
        }
        if metadata.mode() & 0o777 != mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (created, mode, owner);
    Ok(())
}

fn effective_identity() -> CallerIdentity {
    #[cfg(unix)]
    {
        return CallerIdentity {
            uid: nix::unistd::Uid::effective().as_raw(),
            gid: nix::unistd::Gid::effective().as_raw(),
        };
    }
    #[cfg(not(unix))]
    CallerIdentity { uid: 0, gid: 0 }
}

#[cfg(unix)]
fn set_owner(path: &Path, owner: CallerIdentity) -> Result<(), std::io::Error> {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(owner.uid)),
        Some(nix::unistd::Gid::from_raw(owner.gid)),
    )
    .map_err(std::io::Error::from)
}

fn environment_u32(name: &str) -> Result<u32, ServerError> {
    std::env::var(name)
        .map_err(|_| ServerError::CallerIdentity)?
        .parse()
        .map_err(|_| ServerError::CallerIdentity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> CallerIdentity {
        #[cfg(unix)]
        {
            return CallerIdentity {
                uid: nix::unistd::Uid::effective().as_raw(),
                gid: nix::unistd::Gid::effective().as_raw(),
            };
        }
        #[cfg(not(unix))]
        CallerIdentity {
            uid: 1000,
            gid: 1000,
        }
    }

    fn write_request(
        runtime: &ServerRuntime,
        caller: CallerIdentity,
        request: &[u8],
        request_id: Uuid,
    ) {
        runtime.prepare_exchange(caller).unwrap();
        create_private_file(&runtime.paths().request(caller, request_id), request).unwrap();
    }

    async fn exchange(
        runtime: &ServerRuntime,
        caller: CallerIdentity,
        request: &AuthorityRequestEnvelope,
    ) -> AuthorityResponseEnvelope {
        write_request(
            runtime,
            caller,
            &serde_json::to_vec(request).unwrap(),
            request.request_id,
        );
        let response_path = runtime
            .process_request(caller, request.request_id)
            .await
            .unwrap();
        let response = serde_json::from_slice(&std::fs::read(&response_path).unwrap()).unwrap();
        runtime.remove_response(caller, request.request_id).unwrap();
        response
    }

    #[tokio::test]
    async fn info_round_trip_creates_stable_authority_and_private_exchange() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(directory.path());
        let caller = caller();
        let request_id = Uuid::new_v4();
        let request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id,
            appliance_id: None,
            operation: AuthorityOperation::Info,
        };
        write_request(
            &runtime,
            caller,
            &serde_json::to_vec(&request).unwrap(),
            request_id,
        );
        let response_path = runtime.process_request(caller, request_id).await.unwrap();
        assert!(!runtime.paths().request(caller, request_id).exists());
        let response: AuthorityResponseEnvelope =
            serde_json::from_slice(&std::fs::read(&response_path).unwrap()).unwrap();
        let AuthorityResponse::Info(first) = response.result.unwrap() else {
            panic!("expected info response");
        };
        runtime.remove_response(caller, request_id).unwrap();
        assert!(!response_path.exists());

        let second_id = Uuid::new_v4();
        let second = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: second_id,
            appliance_id: Some(first.appliance_id),
            operation: AuthorityOperation::Snapshot {
                known_revision: Some(first.revision),
            },
        };
        write_request(
            &runtime,
            caller,
            &serde_json::to_vec(&second).unwrap(),
            second_id,
        );
        let response_path = runtime.process_request(caller, second_id).await.unwrap();
        let response: AuthorityResponseEnvelope =
            serde_json::from_slice(&std::fs::read(response_path).unwrap()).unwrap();
        assert!(matches!(
            response.result.unwrap(),
            AuthorityResponse::NotModified(info) if info.appliance_id == first.appliance_id
        ));
    }

    #[tokio::test]
    async fn malformed_and_mismatched_requests_fail_closed_without_stdout_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(directory.path());
        let caller = caller();
        let request_id = Uuid::new_v4();
        write_request(&runtime, caller, b"{not-json", request_id);
        let response_path = runtime.process_request(caller, request_id).await.unwrap();
        let response: AuthorityResponseEnvelope =
            serde_json::from_slice(&std::fs::read(response_path).unwrap()).unwrap();
        assert_eq!(
            response.result.unwrap_err().code,
            AuthorityFailureCode::InvalidRequest
        );

        let file_id = Uuid::new_v4();
        let request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: None,
            operation: AuthorityOperation::Info,
        };
        write_request(
            &runtime,
            caller,
            &serde_json::to_vec(&request).unwrap(),
            file_id,
        );
        let response_path = runtime.process_request(caller, file_id).await.unwrap();
        let response: AuthorityResponseEnvelope =
            serde_json::from_slice(&std::fs::read(response_path).unwrap()).unwrap();
        assert_eq!(
            response.result.unwrap_err().code,
            AuthorityFailureCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn lease_commit_and_revision_bound_secret_fetch_dispatch_transactionally() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(directory.path());
        let caller = caller();
        let info_request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: None,
            operation: AuthorityOperation::Info,
        };
        let AuthorityResponse::Info(info) = exchange(&runtime, caller, &info_request)
            .await
            .result
            .unwrap()
        else {
            panic!("expected info response");
        };
        let lease_request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: Some(info.appliance_id),
            operation: AuthorityOperation::AcquireLease {
                expected_revision: 0,
                owner: Uuid::new_v4(),
                scope: "test".into(),
                ttl_seconds: 30,
            },
        };
        let AuthorityResponse::Lease(lease) = exchange(&runtime, caller, &lease_request)
            .await
            .result
            .unwrap()
        else {
            panic!("expected lease response");
        };
        let commit_request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: Some(info.appliance_id),
            operation: AuthorityOperation::Commit {
                lease,
                changes: Box::new(vam_authority::AuthorityChangeSet::default()),
            },
        };
        assert!(matches!(
            exchange(&runtime, caller, &commit_request)
                .await
                .result
                .unwrap(),
            AuthorityResponse::Committed(result) if result.revision == 1
        ));
        let stale_fetch = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: Some(info.appliance_id),
            operation: AuthorityOperation::GetSecrets {
                expected_revision: 0,
                ids: Vec::new(),
            },
        };
        assert_eq!(
            exchange(&runtime, caller, &stale_fetch)
                .await
                .result
                .unwrap_err()
                .code,
            AuthorityFailureCode::RevisionConflict
        );
    }

    #[tokio::test]
    async fn oversized_request_is_rejected_before_json_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::with_limits(directory.path(), 32, 1024);
        let caller = caller();
        let request_id = Uuid::new_v4();
        write_request(&runtime, caller, &[b'x'; 33], request_id);
        assert!(matches!(
            runtime.process_request(caller, request_id).await,
            Err(ServerError::RequestTooLarge { max_bytes: 32 } | ServerError::UnsafeRequest)
        ));
    }

    #[test]
    fn invocation_accepts_only_fixed_commands_and_uuid_arguments() {
        let request_id = Uuid::new_v4();
        assert_eq!(
            parse_invocation([
                OsString::from("vam-server"),
                OsString::from("rpc"),
                OsString::from(request_id.to_string()),
            ])
            .unwrap(),
            Command::Rpc(request_id)
        );
        assert!(
            parse_invocation([
                OsString::from("vam-server"),
                OsString::from("rpc"),
                OsString::from("../../etc/shadow"),
            ])
            .is_err()
        );
        assert!(
            parse_invocation([
                OsString::from("vam-server"),
                OsString::from("prepare"),
                OsString::from("extra"),
            ])
            .is_err()
        );
        assert_eq!(
            parse_invocation([
                OsString::from("vam-server"),
                OsString::from("cleanup"),
                OsString::from(request_id.to_string()),
            ])
            .unwrap(),
            Command::Cleanup(request_id)
        );
    }
}
