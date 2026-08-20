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
    ensure_privileged()?;
    let command = parse_invocation(std::env::args_os())?;
    let caller = CallerIdentity::from_sudo_environment()?;
    let runtime = ServerRuntime::new(MANAGEMENT_ROOT);
    match command {
        Command::Prepare => {
            runtime.prepare_exchange(caller)?;
            Ok(format!("exchange_uid={}", caller.uid))
        }
        Command::Rpc(request_id) => {
            runtime.process_request(caller, request_id).await?;
            Ok(format!("response_ready={request_id}"))
        }
        Command::Cleanup(request_id) => {
            runtime.remove_response(caller, request_id)?;
            Ok(format!("response_removed={request_id}"))
        }
    }
}
