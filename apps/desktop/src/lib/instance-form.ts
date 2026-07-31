import type { VpnBackendKind } from "./types";

export interface InstanceForm {
  display_name: string;
  host_id: string;
  backend: VpnBackendKind;
  endpoint_host: string;
  endpoint_port: number;
  ipv4_subnet: string;
  dns_zone: string;
  routing_mode: "full_tunnel" | "split_tunnel";
  wireguard_userspace_fallback: boolean;
  awg_jc: number;
  awg_jmin: number;
  awg_jmax: number;
  awg_s1: number;
  awg_s2: number;
  awg_s3: number;
  awg_s4: number;
  awg_h1_min: number;
  awg_h1_max: number;
  awg_h2_min: number;
  awg_h2_max: number;
  awg_h3_min: number;
  awg_h3_max: number;
  awg_h4_min: number;
  awg_h4_max: number;
  openvpn_transport: "tcp" | "udp";
  openvpn_cipher: "aes256-gcm" | "chacha20-poly1305";
  openvpn_tls_protection: "tls_crypt" | "none";
  openvpn_certificate_lifetime_days: number;
  ikev2_server_identity: string;
  ikev2_certificate_lifetime_days: number;
  xray_security: "reality" | "tls";
  xray_transport: "tcp" | "xhttp" | "mkcp";
  xray_server_name: string;
  xray_fingerprint: string;
  xray_xhttp_path: string;
  xray_certificate_path: string;
  xray_private_key_path: string;
}

export function newInstanceForm(hostId = "", endpointHost = ""): InstanceForm {
  return {
    display_name: "",
    host_id: hostId,
    backend: "wireguard",
    endpoint_host: endpointHost,
    endpoint_port: 51820,
    ipv4_subnet: "10.64.0.0/24",
    dns_zone: "internal",
    routing_mode: "split_tunnel",
    wireguard_userspace_fallback: false,
    awg_jc: 5,
    awg_jmin: 10,
    awg_jmax: 50,
    awg_s1: 64,
    awg_s2: 96,
    awg_s3: 32,
    awg_s4: 8,
    awg_h1_min: 5,
    awg_h1_max: 999,
    awg_h2_min: 1000,
    awg_h2_max: 1999,
    awg_h3_min: 2000,
    awg_h3_max: 2999,
    awg_h4_min: 3000,
    awg_h4_max: 3999,
    openvpn_transport: "udp",
    openvpn_cipher: "aes256-gcm",
    openvpn_tls_protection: "tls_crypt",
    openvpn_certificate_lifetime_days: 825,
    ikev2_server_identity: endpointHost,
    ikev2_certificate_lifetime_days: 825,
    xray_security: "reality",
    xray_transport: "tcp",
    xray_server_name: "www.cloudflare.com",
    xray_fingerprint: "chrome",
    xray_xhttp_path: "/",
    xray_certificate_path: "",
    xray_private_key_path: "",
  };
}
