import { newInstanceForm, type InstanceForm } from "./instance-form";
import type { BackendSettings, VpnInstance } from "./types";
export function backendSettingsFromForm(form: InstanceForm): BackendSettings {
    switch (form.backend) {
      case "wireguard":
        return {
          backend: "wireguard",
          settings: { userspace_fallback: form.wireguard_userspace_fallback },
        };
      case "amnezia_wg":
        return {
          backend: "amnezia_wg",
          settings: {
            generation: "awg2",
            jc: form.awg_jc,
            jmin: form.awg_jmin,
            jmax: form.awg_jmax,
            s1: form.awg_s1,
            s2: form.awg_s2,
            s3: form.awg_s3,
            s4: form.awg_s4,
            h1: { min: form.awg_h1_min, max: form.awg_h1_max },
            h2: { min: form.awg_h2_min, max: form.awg_h2_max },
            h3: { min: form.awg_h3_min, max: form.awg_h3_max },
            h4: { min: form.awg_h4_min, max: form.awg_h4_max },
          },
        };
      case "openvpn":
        return {
          backend: "openvpn",
          settings: {
            transport: form.openvpn_transport,
            cipher: form.openvpn_cipher,
            tls_protection: form.openvpn_tls_protection,
            certificate_lifetime_days: form.openvpn_certificate_lifetime_days,
          },
        };
      case "ikev2":
        return {
          backend: "ikev2",
          settings: {
            server_identity:
              form.ikev2_server_identity.trim() || form.endpoint_host.trim(),
            certificate_lifetime_days: form.ikev2_certificate_lifetime_days,
          },
        };
      case "xray": throw new Error("Unsupported backend configuration");
    }
  }

export function editFormFromInstance(instance: VpnInstance) {
    const form = newInstanceForm(instance.host_id, instance.endpoint.host);
    Object.assign(form, {
      display_name: instance.display_name,
      backend: instance.backend,
      endpoint_port: instance.endpoint.port,
      ipv4_subnet: instance.network.ipv4_subnet,
      dns_zone: instance.dns.zone,
      routing_mode: instance.routing_mode,
    });
    const settings = instance.backend_settings;
    switch (settings.backend) {
      case "wireguard": form.wireguard_userspace_fallback = settings.settings.userspace_fallback; break;
      case "amnezia_wg": Object.assign(form, {
        awg_jc: settings.settings.jc, awg_jmin: settings.settings.jmin, awg_jmax: settings.settings.jmax,
        awg_s1: settings.settings.s1, awg_s2: settings.settings.s2, awg_s3: settings.settings.s3, awg_s4: settings.settings.s4,
        awg_h1_min: settings.settings.h1.min, awg_h1_max: settings.settings.h1.max,
        awg_h2_min: settings.settings.h2.min, awg_h2_max: settings.settings.h2.max,
        awg_h3_min: settings.settings.h3.min, awg_h3_max: settings.settings.h3.max,
        awg_h4_min: settings.settings.h4.min, awg_h4_max: settings.settings.h4.max,
      }); break;
      case "openvpn": Object.assign(form, {
        openvpn_transport: settings.settings.transport,
        openvpn_cipher: settings.settings.cipher,
        openvpn_tls_protection: settings.settings.tls_protection,
        openvpn_certificate_lifetime_days: settings.settings.certificate_lifetime_days,
      }); break;
      case "ikev2": Object.assign(form, {
        ikev2_server_identity: settings.settings.server_identity,
        ikev2_certificate_lifetime_days: settings.settings.certificate_lifetime_days,
      }); break;
      case "xray": throw new Error("Unsupported backend configuration");
    }
    return form;
  }
