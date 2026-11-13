use std::process::ExitCode;

use vam_server::{
    CallerIdentity, Command, MANAGEMENT_ROOT, ServerRuntime, ensure_privileged, parse_invocation,
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vam-server failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<String, vam_server::ServerError> {
    let command = parse_invocation(std::env::args_os())?;
    // Executable/ABI check for a root-owned upgrade candidate. No storage is opened.
    if matches!(command, Command::SelfCheck) {
        return Ok(
            "vpnctl-helper protocol=2 schema=1 instance_archives_v1 drop_peer_v1 dns_blocking_v1"
                .into(),
        );
    }
    ensure_privileged()?;
    if matches!(command, Command::BlockingRefresh) {
        ServerRuntime::new(MANAGEMENT_ROOT)
            .refresh_due_blocklists()
            .await?;
        return Ok("blocking_refresh_checked".into());
    }
    let caller = CallerIdentity::from_sudo_environment()?;
    let runtime = ServerRuntime::new(MANAGEMENT_ROOT);
    match command {
        Command::SelfCheck | Command::BlockingRefresh => {
            unreachable!("handled without a sudo exchange")
        }
        Command::Prepare => {
            runtime.prepare_exchange(caller)?;
            Ok(format!("exchange_uid={}", caller.uid))
        }
        Command::Rpc(request_id) => {
            runtime.process_request(caller, request_id)?;
            Ok(format!("response_ready={request_id}"))
        }
        Command::ManifestRpc(request_id) => {
            runtime.process_manifest_request(caller, request_id).await?;
            Ok(format!("response_ready={request_id}"))
        }
        Command::Cleanup(request_id) => {
            runtime.cleanup_exchange(caller, request_id)?;
            Ok(format!("exchange_removed={request_id}"))
        }
    }
}
