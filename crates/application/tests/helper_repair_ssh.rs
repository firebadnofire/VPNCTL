use std::{env, fs, sync::Arc};
use tokio_util::sync::CancellationToken;
use vam_application::{ApplicationService, CreateHostInput, HelperPayload};
use vam_ssh::{RusshTransport, SshTransport};
// Run only through tests/helper-update/ssh/run.sh, which creates an isolated
// loopback SSH container and a fresh disposable authentication key.
#[tokio::test]
#[ignore = "requires the disposable SSH repair fixture"]
async fn repairs_an_older_helper_over_verified_ssh_without_deploying() {
    assert_eq!(env::var("VPNCTL_DISPOSABLE_SSH_TEST").as_deref(), Ok("1"));
    let payload = Box::leak(
        fs::read(env::var("VPNCTL_TEST_PAYLOAD").unwrap())
            .unwrap()
            .into_boxed_slice(),
    );
    let transport: Arc<dyn SshTransport> = Arc::new(RusshTransport::default());
    let service = ApplicationService::with_transport(
        vam_storage::Storage::in_memory().await.unwrap(),
        Arc::new(vam_secrets::MemorySecretStore::default()),
        transport.clone(),
    )
    .with_helper_payloads(vec![HelperPayload {
        architecture: "x86_64",
        contents: payload,
    }]);
    let host = service
        .create_host(CreateHostInput {
            display_name: "Disposable SSH fixture".into(),
            hostname: "127.0.0.1".into(),
            port: env::var("VPNCTL_TEST_PORT").unwrap().parse().unwrap(),
            username: "testuser".into(),
            private_key_path: env::var("VPNCTL_TEST_KEY").unwrap().into(),
            passphrase: None,
        })
        .await
        .unwrap();
    let probe = service.probe_host_key(host.id).await.unwrap();
    let trusted = probe.key.public_key_base64.clone();
    service
        .approve_host_key(
            host.id,
            probe.key,
            &env::var("VPNCTL_TEST_FINGERPRINT").unwrap(),
            false,
        )
        .await
        .unwrap();
    let inventory = service.discover_remote(host.id).await.unwrap();
    for cap in ["instance_archives_v1", "drop_peer_v1", "dns_blocking_v1"] {
        assert!(inventory.identity.capabilities.iter().any(|c| c == cap));
    }
    assert!(inventory.discovery.instances.is_empty());
    assert!(inventory.discovery.errors.is_empty());
    assert!(!inventory.cached);
    assert_eq!(service.connected_hosts().await.unwrap(), vec![host.id]);
    let again = service.discover_remote(host.id).await.unwrap();
    assert_eq!(again.identity.appliance_id, inventory.identity.appliance_id);
    let reply=transport.execute(&host.ssh,&trusted,None,"/usr/local/libexec/vam-server self-check && test ! -e /opt/vpn-appliance-manager/instances && find /usr/local/libexec -maxdepth 1 -name 'vam-server.backup-*'",&CancellationToken::new()).await.unwrap();
    assert_eq!(reply.exit_status, 0);
    let text = reply.stdout_text().unwrap();
    assert!(text.contains("protocol=2 schema=1"));
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("vam-server.backup-"))
            .count(),
        1
    );
    service.shutdown_connections().await.unwrap();
    assert!(service.connected_hosts().await.unwrap().is_empty());
    println!(
        "PASS: verified real SSH/SFTP automatic repair, atomic executable replacement, retained backup, capability rediscovery, repeated discovery, no VPN deployment, and connection shutdown"
    );
}
