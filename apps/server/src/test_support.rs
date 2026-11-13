use std::path::Path;
use uuid::Uuid;
use vam_authority::manifest::ManifestStore;
pub fn fixture(root: &Path) -> (ManifestStore, Uuid) {
    use vam_authority::manifest::{Compatibility, Configuration, SaveRequest};
    use vam_core::{
        BackendSettings, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode, VpnBackendKind,
        VpnInstance,
    };
    let appliance = Uuid::new_v4();
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let store = ManifestStore::open(&root.join("control"), appliance).unwrap();
    let input = SaveRequest {
        compatibility: Compatibility::default(),
        appliance_id: appliance,
        request_id: Uuid::new_v4(),
        expected_revision: 0,
        secrets: std::collections::BTreeMap::default(),
        configuration: Configuration {
            instance: VpnInstance {
                id,
                host_id: appliance,
                display_name: "Archived VPN".into(),
                backend: VpnBackendKind::WireGuard,
                backend_settings: BackendSettings::default(),
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: 51820,
                },
                network: NetworkConfig {
                    ipv4_subnet: "10.88.0.0/24".parse().unwrap(),
                    gateway_ipv4: "10.88.0.1".parse().unwrap(),
                    ipv6_subnet: None,
                    gateway_ipv6: None,
                },
                dns: DnsConfig {
                    zone: "vpn.internal".into(),
                    soa_serial: 1,
                },
                routing_mode: RoutingMode::SplitTunnel,
                persistent_keepalive: 25,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            },
            users: vec![],
            peers: vec![],
            dns_records: vec![],
            dns_blocklist_domains: vec![],
        },
    };
    store.save(&input).unwrap();
    (store, id)
}
