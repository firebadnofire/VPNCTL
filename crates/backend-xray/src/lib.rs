use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};
use url::{Host, Url};
use uuid::Uuid;
use vam_backend::{
    BackendCapabilities, BackendError, BackendHealthProbe, BackendRuntimeSpec, BackendValidation,
    ChangeImpact, ClientArtifactKind, ContainerImage, ContainerMount, ServerIdentityStrategy,
    VpnBackend,
};
use vam_core::{
    BackendSettings, DesiredState, Device, DeviceBackendData, ListenerPort, SecretReference,
    TransportProtocol, VpnBackendKind, XrayDeviceData, XraySecurity, XraySettings, XrayTransport,
    validate_device_addresses, validate_instance,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use zeroize::Zeroizing;

pub const XRAY_CONTAINER_PORT: u16 = 8_443;
pub const XRAY_VERSION: &str = "v25.8.3";
pub const XRAY_LOCAL_IMAGE: &str = "vpn-appliance-manager/xray:alpine3.23.5-v25.8.3";
pub const XRAY_DOCKERFILE_PATH: &str = "xray/Dockerfile";
pub const REALITY_PRIVATE_KEY_PATH: &str = "/var/lib/vam-xray/identity/private.key";
pub const REALITY_PUBLIC_KEY_PATH: &str = "/var/lib/vam-xray/identity/public.key";
pub const REALITY_SHORT_ID_PATH: &str = "/var/lib/vam-xray/identity/short-id";

const REALITY_PUBLIC_KEY_LENGTH: usize = 43;
const REALITY_SHORT_ID_LENGTH: usize = 16;
const VISION_FLOW: &str = "xtls-rprx-vision";
const TLS_CERTIFICATE_PATH: &str = "/etc/xray/tls/server.crt";
const TLS_PRIVATE_KEY_PATH: &str = "/etc/xray/tls/server.key";

const XRAY_DOCKERFILE: &str = r#"FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
ARG TARGETARCH
RUN apk add --no-cache \
        ca-certificates=20260611-r0 \
        jq=1.8.1-r0 \
    && apk add --no-cache --virtual .xray-fetch \
        curl=8.20.0-r0 \
        unzip=6.0-r16 \
    && case "${TARGETARCH}" in \
         amd64) \
           asset="Xray-linux-64.zip"; \
           digest="f3f69cdccdf3443f25248f65bec0f621a7bd05c9d6fbbd5d9f064a8fce70f0fc" ;; \
         arm64) \
           asset="Xray-linux-arm64-v8a.zip"; \
           digest="7bcc35d375398c0df4b53ee004fb5b42402fcc0d331db5f2e6ac86cfc12b6a33" ;; \
         *) echo "unsupported Xray target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl --proto '=https' --tlsv1.3 --fail --location --silent --show-error \
         "https://github.com/XTLS/Xray-core/releases/download/v25.8.3/${asset}" \
         --output /tmp/xray.zip \
    && echo "${digest}  /tmp/xray.zip" | sha256sum -c - \
    && unzip -j /tmp/xray.zip xray -d /usr/local/bin \
    && chmod 0755 /usr/local/bin/xray \
    && rm -f /tmp/xray.zip \
    && apk del .xray-fetch \
    && addgroup -S -g 10001 xray \
    && adduser -S -D -H -u 10001 -G xray xray \
    && install -d -o xray -g xray -m 0700 /var/lib/vam-xray
COPY start-xray.sh /usr/local/sbin/start-xray
RUN chmod 0755 /usr/local/sbin/start-xray
USER 10001:10001
ENTRYPOINT ["/usr/local/sbin/start-xray"]
"#;

const XRAY_START_SCRIPT: &str = r#"#!/bin/sh
set -eu
umask 077

readonly config_template=/etc/xray/server-template.json
readonly state_dir=/var/lib/vam-xray
readonly identity_dir="${state_dir}/identity"
readonly active_config="${state_dir}/server.json"
temp_identity=
temp_config="${state_dir}/.server.json.$$"

cleanup() {
    rm -f "${temp_config}"
    if [ -n "${temp_identity}" ]; then
        rm -rf "${temp_identity}"
    fi
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "xray startup: $1" >&2
    exit 1
}

valid_x25519() {
    [ "${#1}" -eq 43 ] || return 1
    case "$1" in
        *[!A-Za-z0-9_-]*) return 1 ;;
    esac
}

valid_short_id() {
    [ "${#1}" -eq 16 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
    esac
}

[ -r "${config_template}" ] || fail "server template is unavailable"
security="$(jq -er '.inbounds[0].streamSettings.security' "${config_template}")" \
    || fail "server template has no security mode"

if [ "${security}" = "reality" ]; then
    if [ ! -e "${identity_dir}" ]; then
        temp_identity="${state_dir}/.identity.$$"
        mkdir -m 0700 "${temp_identity}" || fail "cannot create temporary identity directory"
        key_output="${temp_identity}/key-output"
        xray x25519 > "${key_output}" || fail "xray key generation failed"
        private_key="$(
            awk -F: '
                tolower($1) ~ /^[[:space:]]*private[[:space:]]*key[[:space:]]*$/ {
                    sub(/^[^:]*:[[:space:]]*/, ""); print; exit
                }
            ' "${key_output}"
        )"
        public_key="$(
            awk -F: '
                tolower($1) ~ /^[[:space:]]*(public[[:space:]]*key|password)[[:space:]]*$/ {
                    sub(/^[^:]*:[[:space:]]*/, ""); print; exit
                }
            ' "${key_output}"
        )"
        valid_x25519 "${private_key}" || fail "xray returned an invalid REALITY private key"
        valid_x25519 "${public_key}" || fail "xray returned an invalid REALITY public key"
        short_id="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
        valid_short_id "${short_id}" || fail "kernel RNG returned an invalid REALITY short ID"
        printf '%s\n' "${private_key}" > "${temp_identity}/private.key"
        printf '%s\n' "${public_key}" > "${temp_identity}/public.key"
        printf '%s\n' "${short_id}" > "${temp_identity}/short-id"
        chmod 0600 \
            "${temp_identity}/private.key" \
            "${temp_identity}/public.key" \
            "${temp_identity}/short-id"
        rm -f "${key_output}"
        mv "${temp_identity}" "${identity_dir}" \
            || fail "cannot atomically install REALITY identity"
        temp_identity=
    fi

    [ -d "${identity_dir}" ] || fail "REALITY identity path is not a directory"
    [ -r "${identity_dir}/private.key" ] || fail "REALITY identity is incomplete"
    [ -r "${identity_dir}/public.key" ] || fail "REALITY identity is incomplete"
    [ -r "${identity_dir}/short-id" ] || fail "REALITY identity is incomplete"
    private_key="$(tr -d '\r\n' < "${identity_dir}/private.key")"
    public_key="$(tr -d '\r\n' < "${identity_dir}/public.key")"
    short_id="$(tr -d '\r\n' < "${identity_dir}/short-id")"
    valid_x25519 "${private_key}" || fail "stored REALITY private key is invalid"
    valid_x25519 "${public_key}" || fail "stored REALITY public key is invalid"
    valid_short_id "${short_id}" || fail "stored REALITY short ID is invalid"

    jq --rawfile private_key "${identity_dir}/private.key" \
       --rawfile short_id "${identity_dir}/short-id" '
        ($private_key | rtrimstr("\n") | rtrimstr("\r")) as $private
        | ($short_id | rtrimstr("\n") | rtrimstr("\r")) as $short
        | .inbounds[0].streamSettings.realitySettings.privateKey = $private
        | .inbounds[0].streamSettings.realitySettings.shortIds = [$short]
    ' "${config_template}" > "${temp_config}" \
        || fail "cannot materialize REALITY configuration"
elif [ "${security}" = "tls" ]; then
    jq '.' "${config_template}" > "${temp_config}" \
        || fail "cannot materialize TLS configuration"
else
    fail "unsupported transport security"
fi

chmod 0600 "${temp_config}"
mv "${temp_config}" "${active_config}" || fail "cannot install active Xray configuration"
xray run -test -c "${active_config}" || fail "Xray rejected the rendered configuration"

trap - EXIT HUP INT TERM
exec xray run -c "${active_config}"
"#;

#[derive(Debug, Default)]
pub struct XrayBackend;

impl XrayBackend {
    #[must_use]
    pub fn generate_identity(
        display_name: &str,
        device_id: Uuid,
        transport: XrayTransport,
    ) -> XrayDeviceData {
        let label = slug(display_name);
        XrayDeviceData {
            client_id: Uuid::new_v4(),
            email: format!("{label}-{}@vam.invalid", short_uuid(device_id)),
            flow: (transport == XrayTransport::Tcp).then(|| VISION_FLOW.into()),
        }
    }
}

impl VpnBackend for XrayBackend {
    fn kind(&self) -> VpnBackendKind {
        VpnBackendKind::Xray
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            allocated_tunnel_addresses: false,
            managed_dns: false,
            quick_credential_refresh: false,
            live_identity_updates: false,
            qr_export: true,
            traffic_statistics: false,
            certificate_authority: false,
        }
    }

    fn runtime(&self, settings: &BackendSettings) -> Result<BackendRuntimeSpec, BackendError> {
        let BackendSettings::Xray(settings) = settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        Ok(BackendRuntimeSpec {
            image: ContainerImage::Build {
                tag: XRAY_LOCAL_IMAGE,
                dockerfile_path: XRAY_DOCKERFILE_PATH,
            },
            container_listeners: vec![ListenerPort {
                port: XRAY_CONTAINER_PORT,
                protocol: transport_protocol(settings.transport),
            }],
            capabilities: Vec::new(),
            devices: Vec::new(),
            mounts: vec![
                ContainerMount {
                    host_path: "xray",
                    container_path: "/etc/xray",
                    read_only: true,
                },
                ContainerMount {
                    host_path: "xray-state",
                    container_path: "/var/lib/vam-xray",
                    read_only: false,
                },
            ],
            environment: Vec::new(),
            entrypoint: Vec::new(),
            command: Vec::new(),
            sysctls: Vec::new(),
            identity: ServerIdentityStrategy::StructuredJson,
            validation: BackendValidation::Xray {
                config_path: "/var/lib/vam-xray/server.json",
            },
            health: BackendHealthProbe::Xray,
        })
    }

    fn listeners(&self, settings: &BackendSettings, endpoint_port: u16) -> Vec<ListenerPort> {
        let BackendSettings::Xray(settings) = settings else {
            return Vec::new();
        };
        vec![ListenerPort {
            port: endpoint_port,
            protocol: transport_protocol(settings.transport),
        }]
    }

    fn validate(&self, state: &DesiredState) -> Result<(), BackendError> {
        if state.instance.backend != self.kind() {
            return Err(BackendError::BackendMismatch(self.kind()));
        }
        let BackendSettings::Xray(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        validate_instance(&state.instance)?;
        validate_device_addresses(&state.instance, &state.devices)?;
        validate_endpoint_host(&state.instance.endpoint.host)?;
        validate_settings(settings)?;

        let mut client_ids = HashSet::new();
        let mut emails = HashSet::new();
        for device in state
            .devices
            .iter()
            .filter(|device| device.deleted_at.is_none())
        {
            if device.ipv4_address.is_some()
                || device.ipv6_address.is_some()
                || device.dns_name.is_some()
            {
                return invalid(
                    "device_address",
                    "Xray proxy identities cannot have tunnel or managed DNS addresses",
                );
            }
            let data = xray_device(device, self.kind())?;
            validate_email(&data.email)?;
            validate_flow(data.flow.as_deref(), settings.transport)?;
            if !client_ids.insert(data.client_id) {
                return invalid("client_id", "active Xray client UUIDs must be unique");
            }
            if !emails.insert(data.email.as_str()) {
                return invalid("email", "active Xray client labels must be unique");
            }
        }
        Ok(())
    }

    fn server_secret_references(&self, state: &DesiredState) -> Vec<SecretReference> {
        state
            .instance
            .backend_settings
            .secret_references()
            .into_iter()
            .cloned()
            .collect()
    }

    fn client_secret_references(
        &self,
        device: &Device,
    ) -> Result<Vec<SecretReference>, BackendError> {
        xray_device(device, self.kind())?;
        Ok(Vec::new())
    }

    fn render_server(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, BackendError> {
        self.validate(state)?;
        let BackendSettings::Xray(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let mut files = vec![
            RenderedFile {
                path: XRAY_DOCKERFILE_PATH.into(),
                contents: XRAY_DOCKERFILE.into(),
                mode: 0o644,
                sensitive: false,
            },
            RenderedFile {
                path: "xray/server-template.json".into(),
                contents: render_server_json(state, settings)?,
                mode: 0o600,
                sensitive: true,
            },
            RenderedFile {
                path: "xray/start-xray.sh".into(),
                contents: XRAY_START_SCRIPT.into(),
                mode: 0o700,
                sensitive: false,
            },
            RenderedFile {
                path: "xray-state/.keep".into(),
                contents: String::new(),
                mode: 0o600,
                sensitive: false,
            },
        ];

        if settings.security == XraySecurity::Tls {
            let certificate_ref = settings
                .tls_certificate_ref
                .as_ref()
                .ok_or(BackendError::InvalidKeyMaterial(self.kind()))?;
            let private_key_ref = settings
                .tls_private_key_ref
                .as_ref()
                .ok_or(BackendError::InvalidKeyMaterial(self.kind()))?;
            let certificate = required_secret(secrets, certificate_ref, self.kind())?;
            let private_key = required_secret(secrets, private_key_ref, self.kind())?;
            validate_certificate_pem(certificate.as_str())?;
            validate_private_key_pem(private_key.as_str())?;
            files.extend([
                RenderedFile {
                    path: "xray/tls/server.crt".into(),
                    contents: certificate.to_string(),
                    mode: 0o600,
                    sensitive: true,
                },
                RenderedFile {
                    path: "xray/tls/server.key".into(),
                    contents: private_key.to_string(),
                    mode: 0o600,
                    sensitive: true,
                },
            ]);
        }
        Ok(files)
    }

    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        _secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError> {
        self.validate(state)?;
        if !state
            .devices
            .iter()
            .any(|candidate| candidate.id == device.id && candidate.enabled)
        {
            return invalid("device", "Xray export requires an enabled desired device");
        }
        let BackendSettings::Xray(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let data = xray_device(device, self.kind())?;
        let uri = render_vless_uri(state, device, data, settings)?;
        Ok(ClientArtifact::text(
            format!("{}.vless.txt", slug(&device.display_name)),
            uri,
            None,
        ))
    }

    fn client_artifact_kind(&self) -> ClientArtifactKind {
        ClientArtifactKind::TextConfiguration
    }

    fn classify_settings_change(
        &self,
        previous: &BackendSettings,
        next: &BackendSettings,
    ) -> ChangeImpact {
        let (BackendSettings::Xray(previous), BackendSettings::Xray(next)) = (previous, next)
        else {
            return ChangeImpact::Reinstall;
        };
        if previous.security != next.security
            || previous.reality_public_key != next.reality_public_key
            || previous.reality_short_id != next.reality_short_id
            || previous.tls_certificate_ref != next.tls_certificate_ref
            || previous.tls_private_key_ref != next.tls_private_key_ref
        {
            return ChangeImpact::Reinstall;
        }
        if previous == next || only_fingerprint_changed(previous, next) {
            ChangeImpact::LiveUpdate
        } else {
            ChangeImpact::ServiceRestart
        }
    }
}

fn validate_settings(settings: &XraySettings) -> Result<(), BackendError> {
    validate_server_name(&settings.server_name)?;
    validate_fingerprint(&settings.fingerprint)?;
    validate_xhttp_path(&settings.xhttp_path)?;

    match settings.security {
        XraySecurity::Reality => {
            if settings.transport == XrayTransport::Mkcp {
                return invalid("transport", "REALITY supports raw TCP and XHTTP, not mKCP");
            }
            if settings.tls_certificate_ref.is_some() || settings.tls_private_key_ref.is_some() {
                return invalid(
                    "tls_secret_references",
                    "REALITY settings cannot retain TLS certificate material",
                );
            }
            match (
                settings.reality_public_key.as_deref(),
                settings.reality_short_id.as_deref(),
            ) {
                (Some(public_key), Some(short_id)) => {
                    validate_reality_public_key(public_key)?;
                    validate_reality_short_id(short_id)?;
                }
                (None, None) => {}
                _ => {
                    return invalid(
                        "reality_public_material",
                        "REALITY public key and short ID must be present together",
                    );
                }
            }
        }
        XraySecurity::Tls => {
            if settings.reality_public_key.is_some() || settings.reality_short_id.is_some() {
                return invalid(
                    "reality_public_material",
                    "TLS settings cannot retain REALITY public material",
                );
            }
            if settings.tls_certificate_ref.is_none() || settings.tls_private_key_ref.is_none() {
                return invalid(
                    "tls_secret_references",
                    "TLS requires both certificate and private-key references",
                );
            }
        }
    }
    Ok(())
}

fn validate_endpoint_host(value: &str) -> Result<(), BackendError> {
    Host::parse(value)
        .map(|_| ())
        .map_err(|_| BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "endpoint",
            message: "endpoint must be a valid DNS name or IP address".into(),
        })
}

fn validate_server_name(value: &str) -> Result<(), BackendError> {
    if value.len() > 253
        || value.is_empty()
        || value.ends_with('.')
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return invalid(
            "server_name",
            "server name must be an absolute ASCII DNS name without a trailing dot",
        );
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), BackendError> {
    const ALLOWED: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    if !ALLOWED.contains(&value) {
        return invalid(
            "fingerprint",
            "fingerprint must be a supported browser profile and cannot disable uTLS",
        );
    }
    Ok(())
}

fn validate_xhttp_path(value: &str) -> Result<(), BackendError> {
    if value.is_empty()
        || value.len() > 128
        || !value.starts_with('/')
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(['?', '#'])
    {
        return invalid(
            "xhttp_path",
            "XHTTP path must be a bounded absolute ASCII path without whitespace, query, or fragment",
        );
    }
    Ok(())
}

fn validate_email(value: &str) -> Result<(), BackendError> {
    if value.is_empty()
        || value.len() > 254
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || !matches!(
                    byte,
                    b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'0'..=b'9'
                        | b'.'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'@'
                )
        })
    {
        return invalid("email", "Xray client email/label is invalid");
    }
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        return invalid(
            "email",
            "Xray client email/label must contain exactly one non-edge @",
        );
    }
    Ok(())
}

fn validate_flow(value: Option<&str>, transport: XrayTransport) -> Result<(), BackendError> {
    match (value, transport) {
        (None | Some(""), _) | (Some(VISION_FLOW), XrayTransport::Tcp) => Ok(()),
        (Some(VISION_FLOW), XrayTransport::Xhttp | XrayTransport::Mkcp) => {
            invalid("flow", "xtls-rprx-vision is supported only with raw TCP")
        }
        (Some(_), _) => invalid("flow", "unsupported Xray flow"),
    }
}

fn validate_reality_public_key(value: &str) -> Result<(), BackendError> {
    if value.len() != REALITY_PUBLIC_KEY_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return invalid(
            "reality_public_key",
            "REALITY public key must be a 43-character unpadded base64url value",
        );
    }
    Ok(())
}

fn validate_reality_short_id(value: &str) -> Result<(), BackendError> {
    if value.len() != REALITY_SHORT_ID_LENGTH || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return invalid(
            "reality_short_id",
            "REALITY short ID must contain exactly 16 hexadecimal characters",
        );
    }
    Ok(())
}

fn validate_certificate_pem(value: &str) -> Result<(), BackendError> {
    if value.contains('\0')
        || !value.contains("-----BEGIN CERTIFICATE-----")
        || !value.contains("-----END CERTIFICATE-----")
    {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::Xray));
    }
    Ok(())
}

fn validate_private_key_pem(value: &str) -> Result<(), BackendError> {
    if value.contains('\0')
        || !(value.contains("-----BEGIN PRIVATE KEY-----")
            && value.contains("-----END PRIVATE KEY-----")
            || value.contains("-----BEGIN EC PRIVATE KEY-----")
                && value.contains("-----END EC PRIVATE KEY-----"))
    {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::Xray));
    }
    Ok(())
}

fn render_server_json(
    state: &DesiredState,
    settings: &XraySettings,
) -> Result<String, BackendError> {
    let mut devices: Vec<_> = state
        .devices
        .iter()
        .filter(|device| device.enabled && device.deleted_at.is_none())
        .collect();
    devices.sort_by_key(|device| {
        xray_device(device, VpnBackendKind::Xray)
            .expect("validation rejects non-Xray devices")
            .client_id
    });
    let clients: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let data = xray_device(device, VpnBackendKind::Xray)
                .expect("validation rejects non-Xray devices");
            let mut client = json!({
                "email": data.email,
                "id": data.client_id,
                "level": 0
            });
            if let Some(flow) = data.flow.as_deref().filter(|flow| !flow.is_empty()) {
                client["flow"] = Value::String(flow.into());
            }
            client
        })
        .collect();
    let config = json!({
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": XRAY_CONTAINER_PORT,
            "protocol": "vless",
            "settings": {
                "clients": clients,
                "decryption": "none"
            },
            "streamSettings": render_stream_settings(settings)
        }],
        "log": {
            "loglevel": "error"
        },
        "outbounds": [{
            "protocol": "freedom",
            "tag": "direct"
        }]
    });
    serde_json::to_string_pretty(&config)
        .map(|mut rendered| {
            rendered.push('\n');
            rendered
        })
        .map_err(|error| BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "server_json",
            message: error.to_string(),
        })
}

fn render_stream_settings(settings: &XraySettings) -> Value {
    let mut stream = json!({
        "network": network_name(settings.transport),
        "security": security_name(settings.security)
    });
    match settings.security {
        XraySecurity::Reality => {
            stream["realitySettings"] = json!({
                "dest": format!("{}:443", settings.server_name),
                "maxTimeDiff": 60_000,
                "privateKey": "",
                "serverNames": [settings.server_name],
                "shortIds": [],
                "show": false,
                "xver": 0
            });
        }
        XraySecurity::Tls => {
            stream["tlsSettings"] = json!({
                "alpn": ["h2", "http/1.1"],
                "certificates": [{
                    "certificateFile": TLS_CERTIFICATE_PATH,
                    "keyFile": TLS_PRIVATE_KEY_PATH
                }],
                "maxVersion": "1.3",
                "minVersion": "1.3",
                "rejectUnknownSni": true
            });
        }
    }
    match settings.transport {
        XrayTransport::Tcp => {}
        XrayTransport::Xhttp => {
            stream["xhttpSettings"] = json!({
                "mode": "auto",
                "path": settings.xhttp_path
            });
        }
        XrayTransport::Mkcp => {
            stream["kcpSettings"] = json!({
                "congestion": true,
                "downlinkCapacity": 20,
                "header": {"type": "none"},
                "mtu": 1350,
                "readBufferSize": 2,
                "tti": 50,
                "uplinkCapacity": 5,
                "writeBufferSize": 2
            });
        }
    }
    stream
}

fn render_vless_uri(
    state: &DesiredState,
    device: &Device,
    data: &XrayDeviceData,
    settings: &XraySettings,
) -> Result<String, BackendError> {
    let mut uri = Url::parse("vless://placeholder.invalid").map_err(|error| {
        BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "client_uri",
            message: error.to_string(),
        }
    })?;
    uri.set_username(&data.client_id.to_string())
        .map_err(|()| BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "client_id",
            message: "client ID cannot be encoded as URL user information".into(),
        })?;
    uri.set_host(Some(&state.instance.endpoint.host))
        .map_err(|error| BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "endpoint",
            message: error.to_string(),
        })?;
    uri.set_port(Some(state.instance.endpoint.port))
        .map_err(|()| BackendError::InvalidSetting {
            backend: VpnBackendKind::Xray,
            field: "endpoint_port",
            message: "endpoint port cannot be encoded".into(),
        })?;
    {
        let mut query = uri.query_pairs_mut();
        query
            .append_pair("encryption", "none")
            .append_pair("security", security_name(settings.security))
            .append_pair("sni", &settings.server_name)
            .append_pair("fp", &settings.fingerprint)
            .append_pair("type", uri_transport_name(settings.transport));
        if let Some(flow) = data.flow.as_deref().filter(|flow| !flow.is_empty()) {
            query.append_pair("flow", flow);
        }
        match settings.security {
            XraySecurity::Reality => {
                let public_key = settings.reality_public_key.as_deref().ok_or_else(|| {
                    BackendError::InvalidSetting {
                        backend: VpnBackendKind::Xray,
                        field: "reality_public_key",
                        message: "verified remote REALITY public material is required for export"
                            .into(),
                    }
                })?;
                let short_id = settings.reality_short_id.as_deref().ok_or_else(|| {
                    BackendError::InvalidSetting {
                        backend: VpnBackendKind::Xray,
                        field: "reality_short_id",
                        message: "verified remote REALITY public material is required for export"
                            .into(),
                    }
                })?;
                query
                    .append_pair("pbk", public_key)
                    .append_pair("sid", short_id)
                    .append_pair("spx", "/");
            }
            XraySecurity::Tls => {
                query.append_pair("alpn", "h2,http/1.1");
            }
        }
        match settings.transport {
            XrayTransport::Tcp => {}
            XrayTransport::Xhttp => {
                query
                    .append_pair("path", &settings.xhttp_path)
                    .append_pair("mode", "auto");
            }
            XrayTransport::Mkcp => {
                query.append_pair("headerType", "none");
            }
        }
    }
    uri.set_fragment(Some(&device.display_name));
    Ok(uri.into())
}

fn required_secret<'a>(
    secrets: &'a HashMap<SecretReference, Zeroizing<String>>,
    reference: &SecretReference,
    backend: VpnBackendKind,
) -> Result<&'a Zeroizing<String>, BackendError> {
    secrets
        .get(reference)
        .ok_or_else(|| BackendError::MissingSecret {
            backend,
            reference: reference.clone(),
        })
}

fn xray_device(device: &Device, backend: VpnBackendKind) -> Result<&XrayDeviceData, BackendError> {
    let DeviceBackendData::Xray(data) = &device.backend_data else {
        return Err(BackendError::BackendMismatch(backend));
    };
    Ok(data)
}

const fn transport_protocol(transport: XrayTransport) -> TransportProtocol {
    match transport {
        XrayTransport::Tcp | XrayTransport::Xhttp => TransportProtocol::Tcp,
        XrayTransport::Mkcp => TransportProtocol::Udp,
    }
}

const fn network_name(transport: XrayTransport) -> &'static str {
    match transport {
        XrayTransport::Tcp => "tcp",
        XrayTransport::Xhttp => "xhttp",
        XrayTransport::Mkcp => "kcp",
    }
}

const fn uri_transport_name(transport: XrayTransport) -> &'static str {
    match transport {
        XrayTransport::Tcp => "tcp",
        XrayTransport::Xhttp => "xhttp",
        XrayTransport::Mkcp => "kcp",
    }
}

const fn security_name(security: XraySecurity) -> &'static str {
    match security {
        XraySecurity::Tls => "tls",
        XraySecurity::Reality => "reality",
    }
}

fn only_fingerprint_changed(previous: &XraySettings, next: &XraySettings) -> bool {
    XraySettings {
        fingerprint: next.fingerprint.clone(),
        ..previous.clone()
    } == *next
}

fn short_uuid(id: Uuid) -> String {
    let value = id.simple().to_string();
    value[value.len() - 12..].into()
}

fn slug(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "xray-client".into()
    } else {
        slug.into()
    }
}

fn invalid<T>(field: &'static str, message: impl Into<String>) -> Result<T, BackendError> {
    Err(BackendError::InvalidSetting {
        backend: VpnBackendKind::Xray,
        field,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vam_core::{
        DnsConfig, EndpointConfig, NetworkConfig, RoutingMode, VpnInstance, XraySecurity,
        first_usable,
    };

    fn fixture(
        security: XraySecurity,
        transport: XrayTransport,
    ) -> (
        DesiredState,
        Device,
        HashMap<SecretReference, Zeroizing<String>>,
    ) {
        let instance_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let certificate_ref = SecretReference(Uuid::from_u128(3));
        let private_key_ref = SecretReference(Uuid::from_u128(4));
        let settings = XraySettings {
            security,
            transport,
            server_name: "www.example.test".into(),
            fingerprint: "chrome".into(),
            xhttp_path: "/vpn-path".into(),
            reality_public_key: (security == XraySecurity::Reality)
                .then(|| "A".repeat(REALITY_PUBLIC_KEY_LENGTH)),
            reality_short_id: (security == XraySecurity::Reality)
                .then(|| "0123456789abcdef".into()),
            tls_certificate_ref: (security == XraySecurity::Tls).then(|| certificate_ref.clone()),
            tls_private_key_ref: (security == XraySecurity::Tls).then(|| private_key_ref.clone()),
        };
        let subnet = "10.89.0.0/24".parse().unwrap();
        let instance = VpnInstance {
            id: instance_id,
            host_id: Uuid::from_u128(10),
            display_name: "Xray".into(),
            backend: VpnBackendKind::Xray,
            backend_settings: BackendSettings::Xray(settings),
            endpoint: EndpointConfig {
                host: "vpn.example.test".into(),
                port: 9443,
            },
            network: NetworkConfig {
                ipv4_subnet: subnet,
                gateway_ipv4: first_usable(subnet).unwrap(),
                ipv6_subnet: None,
                gateway_ipv6: None,
            },
            dns: DnsConfig {
                zone: "vpn.internal".into(),
                soa_serial: 2_026_073_001,
            },
            routing_mode: RoutingMode::SplitTunnel,
            persistent_keepalive: 25,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        let data = XrayDeviceData {
            client_id: Uuid::from_u128(100),
            email: "work-laptop-000000000002@vam.invalid".into(),
            flow: (transport == XrayTransport::Tcp).then(|| VISION_FLOW.into()),
        };
        let device = Device {
            id: device_id,
            instance_id,
            user_id: None,
            display_name: "Work Laptop".into(),
            ipv4_address: None,
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            backend_data: DeviceBackendData::Xray(data),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let state = DesiredState {
            instance,
            users: Vec::new(),
            devices: vec![device.clone()],
            dns_records: Vec::new(),
            dns_blocklist_domains: Vec::new(),
        };
        let secrets = HashMap::from([
            (
                certificate_ref,
                Zeroizing::new(
                    "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n".into(),
                ),
            ),
            (
                private_key_ref,
                Zeroizing::new(
                    "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n".into(),
                ),
            ),
        ]);
        (state, device, secrets)
    }

    #[test]
    fn identity_generation_is_unique_and_transport_aware() {
        let first =
            XrayBackend::generate_identity("Work Laptop", Uuid::from_u128(1), XrayTransport::Tcp);
        let second =
            XrayBackend::generate_identity("Work Laptop", Uuid::from_u128(2), XrayTransport::Xhttp);
        assert_ne!(first.client_id, second.client_id);
        assert_ne!(first.email, second.email);
        assert_eq!(first.flow.as_deref(), Some(VISION_FLOW));
        assert!(second.flow.is_none());
        validate_email(&first.email).unwrap();
        validate_email(&second.email).unwrap();
    }

    #[test]
    fn runtime_is_verified_multiarch_non_root_and_unprivileged() {
        let (state, _, _) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        let runtime = XrayBackend
            .runtime(&state.instance.backend_settings)
            .unwrap();
        assert!(matches!(
            runtime.image,
            ContainerImage::Build {
                tag: XRAY_LOCAL_IMAGE,
                dockerfile_path: XRAY_DOCKERFILE_PATH
            }
        ));
        assert!(runtime.capabilities.is_empty());
        assert!(runtime.devices.is_empty());
        assert!(runtime.sysctls.is_empty());
        assert_eq!(
            runtime.container_listeners,
            vec![ListenerPort {
                port: XRAY_CONTAINER_PORT,
                protocol: TransportProtocol::Tcp
            }]
        );
        assert!(XRAY_DOCKERFILE.contains("USER 10001:10001"));
        assert!(XRAY_DOCKERFILE.contains("sha256sum -c -"));
        assert!(XRAY_DOCKERFILE.contains("f3f69cdccdf3443f25248f65bec0f621"));
        assert!(XRAY_DOCKERFILE.contains("7bcc35d375398c0df4b53ee004fb5b4"));
        assert!(XRAY_DOCKERFILE.contains("--tlsv1.3"));
        assert!(!XRAY_DOCKERFILE.contains("--privileged"));
        assert!(!XRAY_DOCKERFILE.contains("latest"));
    }

    #[test]
    fn reality_server_json_is_structured_sorted_and_contains_no_private_key() {
        let (mut state, device, secrets) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        let mut second = device;
        second.id = Uuid::from_u128(3);
        second.display_name = "Phone".into();
        second.backend_data = DeviceBackendData::Xray(XrayDeviceData {
            client_id: Uuid::from_u128(50),
            email: "phone@vam.invalid".into(),
            flow: Some(VISION_FLOW.into()),
        });
        state.devices.insert(0, second);
        let files = XrayBackend.render_server(&state, &secrets).unwrap();
        let template = files
            .iter()
            .find(|file| file.path == "xray/server-template.json")
            .unwrap();
        assert!(template.sensitive);
        let value: Value = serde_json::from_str(&template.contents).unwrap();
        let clients = value["inbounds"][0]["settings"]["clients"]
            .as_array()
            .unwrap();
        assert_eq!(
            clients[0]["id"],
            Value::String(Uuid::from_u128(50).to_string())
        );
        assert_eq!(clients[1]["email"], "work-laptop-000000000002@vam.invalid");
        assert_eq!(
            value["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"],
            ""
        );
        assert_eq!(
            value["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"],
            json!([])
        );
        assert!(!template.contents.contains("BEGIN PRIVATE"));
        assert!(
            !template
                .contents
                .contains(&"A".repeat(REALITY_PUBLIC_KEY_LENGTH))
        );
        assert!(XRAY_START_SCRIPT.contains("jq --rawfile private_key"));
        assert!(!XRAY_START_SCRIPT.contains("--arg private_key"));
        assert!(XRAY_START_SCRIPT.contains("xray run -test"));
        assert!(XRAY_START_SCRIPT.contains("exec xray run"));
        assert!(!XRAY_START_SCRIPT.contains("sed "));
        assert!(!XRAY_START_SCRIPT.contains("tail -f"));
        assert!(!XRAY_START_SCRIPT.contains("iptables"));
    }

    #[test]
    fn tls_xhttp_renders_tls13_material_without_insecure_bypass() {
        let (state, _, secrets) = fixture(XraySecurity::Tls, XrayTransport::Xhttp);
        let files = XrayBackend.render_server(&state, &secrets).unwrap();
        let template = files
            .iter()
            .find(|file| file.path == "xray/server-template.json")
            .unwrap();
        let value: Value = serde_json::from_str(&template.contents).unwrap();
        let stream = &value["inbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["minVersion"], "1.3");
        assert_eq!(stream["tlsSettings"]["maxVersion"], "1.3");
        assert_eq!(stream["tlsSettings"]["rejectUnknownSni"], true);
        assert_eq!(stream["xhttpSettings"]["path"], "/vpn-path");
        assert!(!template.contents.contains("allowInsecure"));
        assert!(files.iter().any(|file| {
            file.path == "xray/tls/server.crt" && file.sensitive && file.mode == 0o600
        }));
        assert!(files.iter().any(|file| {
            file.path == "xray/tls/server.key" && file.sensitive && file.mode == 0o600
        }));
    }

    #[test]
    fn mkcp_uses_udp_and_reality_rejects_it() {
        let (tls, _, _) = fixture(XraySecurity::Tls, XrayTransport::Mkcp);
        assert_eq!(
            XrayBackend.listeners(&tls.instance.backend_settings, 9443),
            vec![ListenerPort {
                port: 9443,
                protocol: TransportProtocol::Udp
            }]
        );
        let runtime = XrayBackend.runtime(&tls.instance.backend_settings).unwrap();
        assert_eq!(
            runtime.container_listeners[0].protocol,
            TransportProtocol::Udp
        );

        let (mut reality, _, _) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        let BackendSettings::Xray(settings) = &mut reality.instance.backend_settings else {
            unreachable!()
        };
        settings.transport = XrayTransport::Mkcp;
        assert!(matches!(
            XrayBackend.validate(&reality),
            Err(BackendError::InvalidSetting {
                field: "transport",
                ..
            })
        ));
    }

    #[test]
    fn vless_export_is_url_encoded_and_requires_reality_public_material() {
        let (state, device, secrets) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        let artifact = XrayBackend
            .render_client(&state, &device, &secrets)
            .unwrap();
        assert_eq!(artifact.suggested_filename, "work-laptop.vless.txt");
        let text = artifact.contents.as_text().unwrap();
        let parsed = Url::parse(text).unwrap();
        let expected_client_id = xray_device(&device, VpnBackendKind::Xray)
            .unwrap()
            .client_id
            .to_string();
        assert_eq!(parsed.scheme(), "vless");
        assert_eq!(parsed.username(), expected_client_id);
        assert_eq!(parsed.host_str(), Some("vpn.example.test"));
        assert_eq!(parsed.port(), Some(9443));
        let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query.get("security").map(String::as_str), Some("reality"));
        assert_eq!(query.get("type").map(String::as_str), Some("tcp"));
        assert_eq!(query.get("flow").map(String::as_str), Some(VISION_FLOW));
        assert_eq!(
            query.get("sid").map(String::as_str),
            Some("0123456789abcdef")
        );
        assert_eq!(parsed.fragment(), Some("Work%20Laptop"));

        let mut missing = state;
        let BackendSettings::Xray(settings) = &mut missing.instance.backend_settings else {
            unreachable!()
        };
        settings.reality_public_key = None;
        settings.reality_short_id = None;
        assert!(matches!(
            XrayBackend.render_client(&missing, &device, &secrets),
            Err(BackendError::InvalidSetting {
                field: "reality_public_key",
                ..
            })
        ));
    }

    #[test]
    fn desired_state_reconciliation_removes_disabled_and_replaced_ids() {
        let (mut state, device, secrets) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        let original = xray_device(&device, VpnBackendKind::Xray)
            .unwrap()
            .client_id;
        state.devices[0].enabled = false;
        let disabled = XrayBackend.render_server(&state, &secrets).unwrap();
        let disabled_json: Value = serde_json::from_str(
            &disabled
                .iter()
                .find(|file| file.path == "xray/server-template.json")
                .unwrap()
                .contents,
        )
        .unwrap();
        assert!(
            disabled_json["inbounds"][0]["settings"]["clients"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        state.devices[0].enabled = true;
        state.devices[0].backend_data = DeviceBackendData::Xray(XrayBackend::generate_identity(
            "Work Laptop",
            device.id,
            XrayTransport::Tcp,
        ));
        let replaced = XrayBackend.render_server(&state, &secrets).unwrap();
        let replaced_text = &replaced
            .iter()
            .find(|file| file.path == "xray/server-template.json")
            .unwrap()
            .contents;
        assert!(!replaced_text.contains(&original.to_string()));
    }

    #[test]
    fn unsafe_values_and_address_semantics_are_rejected() {
        let (mut state, _, _) = fixture(XraySecurity::Reality, XrayTransport::Tcp);
        if let BackendSettings::Xray(settings) = &mut state.instance.backend_settings {
            settings.fingerprint = "unsafe".into();
        }
        assert!(matches!(
            XrayBackend.validate(&state),
            Err(BackendError::InvalidSetting {
                field: "fingerprint",
                ..
            })
        ));
        if let BackendSettings::Xray(settings) = &mut state.instance.backend_settings {
            settings.fingerprint = "chrome".into();
            settings.xhttp_path = "/bad?query".into();
        }
        assert!(matches!(
            XrayBackend.validate(&state),
            Err(BackendError::InvalidSetting {
                field: "xhttp_path",
                ..
            })
        ));
        if let BackendSettings::Xray(settings) = &mut state.instance.backend_settings {
            settings.xhttp_path = "/".into();
        }
        state.devices[0].ipv4_address = Some("10.89.0.2".parse().unwrap());
        assert!(matches!(
            XrayBackend.validate(&state),
            Err(BackendError::InvalidSetting {
                field: "device_address",
                ..
            })
        ));
    }

    #[test]
    fn settings_change_classification_preserves_server_identity() {
        let original = XraySettings::default();
        let mut fingerprint = original.clone();
        fingerprint.fingerprint = "firefox".into();
        assert_eq!(
            XrayBackend.classify_settings_change(
                &BackendSettings::Xray(original.clone()),
                &BackendSettings::Xray(fingerprint)
            ),
            ChangeImpact::LiveUpdate
        );
        let mut path = original.clone();
        path.xhttp_path = "/new".into();
        assert_eq!(
            XrayBackend.classify_settings_change(
                &BackendSettings::Xray(original.clone()),
                &BackendSettings::Xray(path)
            ),
            ChangeImpact::ServiceRestart
        );
        let mut identity = original.clone();
        identity.reality_short_id = Some("0123456789abcdef".into());
        identity.reality_public_key = Some("A".repeat(REALITY_PUBLIC_KEY_LENGTH));
        assert_eq!(
            XrayBackend.classify_settings_change(
                &BackendSettings::Xray(original),
                &BackendSettings::Xray(identity)
            ),
            ChangeImpact::Reinstall
        );
    }
}
