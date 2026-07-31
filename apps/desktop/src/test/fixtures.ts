import type {
  BackendOption,
  Client,
  InstanceSummary,
  VpnBackendKind,
  VpnInstance,
} from "../lib/types";

const names: Record<VpnBackendKind, [string, string]> = {
  wireguard: ["WireGuard", "WG"],
  amnezia_wg: ["AmneziaWG 2", "AWG2"],
  openvpn: ["OpenVPN", "OVPN"],
  ikev2: ["IKEv2 / IPsec", "IKEv2"],
  xray: ["Xray VLESS", "VLESS"],
};

export const backendOptions: BackendOption[] = (
  Object.keys(names) as VpnBackendKind[]
).map((kind) => {
  const routed = kind !== "xray";
  const [displayName, badge] = names[kind];
  return {
    kind,
    display_name: displayName,
    default_port: kind === "ikev2" ? 500 : 443,
    capabilities: {
      allocated_tunnel_addresses: routed,
      managed_dns: routed,
      quick_credential_refresh: kind === "wireguard" || kind === "amnezia_wg",
      live_identity_updates: kind === "xray",
      qr_export: kind === "wireguard" || kind === "amnezia_wg" || kind === "xray",
      traffic_statistics: false,
      certificate_authority: kind === "openvpn" || kind === "ikev2",
    },
    presentation: {
      short_name: badge,
      badge,
      description: `${displayName} managed backend`,
      routing: routed ? "routed_tunnel" : "proxy",
      dns: routed ? "managed_private_dns" : "unsupported",
      client_addresses: routed ? "allocated" : "none",
      statistics: "unavailable",
      listener_model: kind === "ikev2" ? "fixed_multiple" : "configurable",
      client_identity_name: kind === "xray" ? "VLESS identity" : "Client identity",
      client_actions: ["export", "remove"],
      export_formats:
        kind === "wireguard"
          ? ["wire_guard_configuration"]
          : kind === "amnezia_wg"
            ? ["amnezia_wg_configuration"]
            : kind === "openvpn"
              ? ["open_vpn_profile"]
              : kind === "ikev2"
                ? ["protected_pkcs12"]
                : ["vless_uri"],
      configuration_sections: routed
        ? ["general", "network", "protocol", "dns", "advanced"]
        : ["general", "protocol", "advanced"],
      configuration_fields: ["endpoint", "listener_port"],
      host_requirements: ["linux", "docker_engine", "compose_v2"],
      identity_replacement_warning: `Replacing this ${displayName} identity requires a new export.`,
    },
  };
});

export function instance(kind: VpnBackendKind = "xray"): VpnInstance {
  const backend_settings =
    kind === "xray"
      ? ({
          backend: "xray",
          settings: {
            security: "reality",
            transport: "tcp",
            server_name: "www.example.com",
            fingerprint: "chrome",
            xhttp_path: "/",
          },
        } as const)
      : ({ backend: "wireguard", settings: { userspace_fallback: false } } as const);
  return {
    id: `instance-${kind}`,
    host_id: "host-1",
    display_name: `${names[kind][0]} appliance`,
    backend: kind,
    backend_settings: backend_settings as VpnInstance["backend_settings"],
    endpoint: { host: "vpn.example.com", port: 443 },
    network: { ipv4_subnet: "10.64.0.0/24", gateway_ipv4: "10.64.0.1" },
    dns: { zone: "internal", soa_serial: 1 },
    routing_mode: "split_tunnel",
    persistent_keepalive: 25,
    created_at: "2026-07-31T12:00:00Z",
    updated_at: "2026-07-31T12:00:00Z",
  };
}

export function summary(kind: VpnBackendKind = "xray"): InstanceSummary {
  return {
    instance: instance(kind),
    secondary_summary: kind === "xray" ? "VLESS proxy" : "Routed tunnel",
    listener_summary: kind === "ikev2" ? "UDP 500 + 4500" : "TCP 443",
    client_count: 1,
    state: "unknown",
    state_evidence: "deployment_history",
    observed_at: null,
    last_deployment: null,
  };
}

export function client(kind: VpnBackendKind = "xray"): Client {
  const qr = kind === "wireguard" || kind === "amnezia_wg" || kind === "xray";
  return {
    id: `client-${kind}`,
    instance_id: `instance-${kind}`,
    display_name: `${names[kind][0]} client`,
    ipv4_address: kind === "xray" ? null : "10.64.0.2",
    enabled: true,
    backend: kind,
    identity_summary: kind === "xray" ? "VLESS identity · flow xtls-rprx-vision" : "Public identity …ABCD",
    state_label: "Enabled",
    actions: [
      { action: "export", label: "Export profile", destructive: false },
      ...(qr ? [{ action: "qr_export" as const, label: "Show QR", destructive: false }] : []),
      { action: "remove", label: "Remove client", warning: "Existing exports stop working.", destructive: true },
    ],
    export_formats: backendOptions.find((option) => option.kind === kind)!.presentation.export_formats,
    statistics: null,
    created_at: "2026-07-31T12:00:00Z",
  };
}
