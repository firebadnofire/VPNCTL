//! Independent, appliance-owned DNS blocklist updates. Desired VPN revisions are
//! never advanced or deployed by this subsystem.
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;
use vam_authority::{
    AuthorityError,
    manifest::{
        ManifestStore, Reply, RuntimeContext,
        blocking::{Action, MAX_DOMAINS, Policy, Receipt, Source, SourceStatus, State, View},
    },
};

fn invalid(message: &str) -> AuthorityError {
    AuthorityError::InvalidState(message.into())
}
fn view(state: State) -> Reply {
    Reply::Blocking(Box::new(View {
        state,
        scheduler_available: scheduler_available(),
    }))
}
pub fn scheduler_available() -> bool {
    std::path::Path::new("/run/systemd/system").is_dir()
}
fn validate_policy(policy: &Policy) -> Result<(), AuthorityError> {
    if !(1..=365).contains(&policy.interval_days) {
        return Err(invalid("Refresh interval must be between 1 and 365 days."));
    }
    if policy.sources.len() > 64 {
        return Err(invalid(
            "At most 64 blocking sources are supported per instance.",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for source in &policy.sources {
        if source.name.trim().is_empty() || source.name.len() > 128 {
            return Err(invalid(
                "Each source needs a name of at most 128 characters.",
            ));
        }
        let normalized = validate_url(&source.url)?.to_string();
        if !ids.insert(source.id) || !urls.insert(normalized) {
            return Err(invalid("Source IDs and URLs must be unique."));
        }
    }
    Ok(())
}
fn validate_url(value: &str) -> Result<url::Url, AuthorityError> {
    let url =
        url::Url::parse(value).map_err(|_| invalid("Enter a valid HTTP or HTTPS source URL."))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "Sources require HTTP/HTTPS URLs without credentials or fragments.",
        ));
    }
    if value.len() > 2048 {
        return Err(invalid("Source URL exceeds 2048 characters."));
    }
    Ok(url)
}

pub async fn execute(
    store: &ManifestStore,
    instance_id: Uuid,
    request_id: Uuid,
    action: Action,
) -> Result<Reply, AuthorityError> {
    let context = store.runtime_context(instance_id, None)?;
    let action = if matches!(action, Action::Resume) {
        context
            .blocking_intent(request_id)?
            .ok_or_else(|| {
                invalid("Blocking request intent is unavailable; inspect the pending operation.")
            })?
            .action
    } else {
        action
    };
    let mut state = context.blocking_state()?;
    if matches!(action, Action::Read) {
        if let Some(pending) = context.pending_operation()?
            && context.blocking_intent(pending)?.is_some()
        {
            state.pending_request = Some(pending);
        }
        return Ok(view(state));
    }
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&action)?));
    if let Some(receipt) = context.blocking_receipt(request_id)? {
        if receipt.request_hash != hash {
            return Err(invalid(
                "Blocking request ID reused with different content.",
            ));
        }
        if context.pending_operation()? == Some(request_id) {
            context.store_blocking_state(&receipt.state)?;
            context.finish_mutation()?;
        }
        return Ok(view(receipt.state));
    }
    let expected = match &action {
        Action::Save {
            expected_revision, ..
        }
        | Action::Refresh { expected_revision } => *expected_revision,
        Action::Read | Action::Resume => unreachable!(),
    };
    if let Some(intent) = context.blocking_intent(request_id)?
        && intent.request_hash != hash
    {
        return Err(invalid(
            "Blocking request ID reused with different content.",
        ));
    }
    let resuming = state.pending_request == Some(request_id)
        && context.pending_operation()? == Some(request_id);
    if !resuming && state.policy.revision != expected {
        return Err(AuthorityError::RevisionConflict {
            expected,
            actual: state.policy.revision,
        });
    }
    if !resuming {
        if let Action::Save { policy, .. } = &action {
            validate_policy(policy)?;
        }
        context.record_blocking_intent(
            request_id,
            &vam_authority::manifest::blocking::Intent {
                action: action.clone(),
                request_hash: hash.clone(),
            },
        )?;
        if context.pending_operation()? != Some(request_id) {
            context.begin_mutation(request_id)?;
        }
        state.pending_request = Some(request_id);
        if let Action::Save { policy, .. } = &action {
            let mut policy = policy.clone();
            policy.revision = expected
                .checked_add(1)
                .ok_or_else(|| invalid("Blocking revision limit reached."))?;
            for source in &mut policy.sources {
                source.name = source.name.trim().to_owned();
                source.url = validate_url(&source.url)?.to_string();
            }
            state.policy = policy;
        }
        context.store_blocking_state(&state)?;
    }
    state.last_attempt = Some(Utc::now());
    state.error = None;
    context.store_blocking_state(&state)?;
    let result = async {
        if matches!(action, Action::Save { .. })
            && state.policy.enabled
            && state.policy.schedule_enabled
            && state.policy.sources.iter().any(|source| source.enabled)
            && scheduler_available()
        {
            install_schedule().await?;
        }
        refresh(&context, &mut state).await
    }
    .await;
    if let Err(error) = result {
        state.error = Some(error.to_string());
    }
    if state.apply_journal.is_some() {
        context.store_blocking_state(&state)?;
        return Ok(view(state));
    }
    state.pending_request = None;
    // Publish the receipt first. A crash at any later point can finish the
    // state publication from that receipt without repeating a changed action.
    context.record_blocking(
        request_id,
        &Receipt {
            request_hash: hash,
            state: state.clone(),
        },
    )?;
    context.store_blocking_state(&state)?;
    context.finish_mutation()?;
    Ok(view(state))
}
fn allowed_address(address: std::net::IpAddr, allow_test_loopback: bool) -> bool {
    use std::net::IpAddr;
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            (allow_test_loopback || !ip.is_loopback())
                && !ip.is_unspecified()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && ip != std::net::Ipv4Addr::BROADCAST
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return allowed_address(IpAddr::V4(mapped), allow_test_loopback);
            }
            (allow_test_loopback || !ip.is_loopback())
                && !ip.is_unspecified()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
                && ip
                    != "fd00:ec2::254"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("constant address")
        }
    }
}
async fn fetch(source: &Source) -> Result<Vec<String>, AuthorityError> {
    fetch_with_policy(source, false).await
}
async fn fetch_with_policy(
    source: &Source,
    allow_test_loopback: bool,
) -> Result<Vec<String>, AuthorityError> {
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_inner(source, allow_test_loopback),
    )
    .await
    .map_err(|_| invalid("Source download exceeded the 30-second timeout."))?
}
async fn fetch_inner(
    source: &Source,
    allow_test_loopback: bool,
) -> Result<Vec<String>, AuthorityError> {
    const MAX_BYTES: usize = 20 * 1024 * 1024;
    let mut url = validate_url(&source.url)?;
    let mut used_https = url.scheme() == "https";
    for hop in 0..=5 {
        let host = url
            .host_str()
            .ok_or_else(|| invalid("Source URL has no hostname."))?;
        let hostname = host.trim_matches(['[', ']']);
        let port = url
            .port_or_known_default()
            .ok_or_else(|| invalid("Source URL has no valid port."))?;
        let addresses: Vec<_> = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|_| invalid("Source hostname could not be resolved."))?
            .collect();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| !allowed_address(address.ip(), allow_test_loopback))
        {
            return Err(invalid(
                "Source addresses must not resolve to loopback, link-local, shared-address metadata, unspecified, or multicast networks.",
            ));
        }
        // Pin the checked addresses for this request, preserving the hostname for
        // certificate/SNI checks. Proxies and automatic redirects cannot bypass it.
        let client = reqwest::Client::builder()
            .no_proxy()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .user_agent("VPNCTL/blocking-refresh")
            .build()
            .map_err(|_| invalid("Could not initialize the verified HTTP client."))?;
        let mut response = client.get(url.clone()).send().await.map_err(|_| {
            invalid("Source download failed. Check connectivity and certificate trust.")
        })?;
        if response.status().is_redirection() {
            if hop == 5 {
                return Err(invalid("Source exceeded five redirects."));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| invalid("Source redirect has no valid destination."))?;
            let next = url
                .join(location)
                .map_err(|_| invalid("Source redirect has an invalid destination."))?;
            validate_url(next.as_str())?;
            if used_https && next.scheme() == "http" {
                return Err(invalid("HTTPS-to-HTTP redirects are forbidden."));
            }
            used_https |= next.scheme() == "https";
            url = next;
            continue;
        }
        response = response
            .error_for_status()
            .map_err(|_| invalid("Source returned an unsuccessful HTTP status."))?;
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BYTES as u64)
        {
            return Err(invalid("Source exceeds the 20 MiB download limit."));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("Source transfer failed or timed out."))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
                return Err(invalid("Source exceeds the 20 MiB download limit."));
            }
            bytes.extend_from_slice(&chunk);
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("Source must contain UTF-8 hosts or domain-list text."))?;
        let domains = vam_dns::parse_hostslist_domains_bounded(text, MAX_DOMAINS)
            .map_err(|_| invalid("Source exceeds one million unique domains."))?;
        if domains.is_empty() {
            return Err(invalid(
                "Source contained no usable blocked domains. The working dataset was preserved.",
            ));
        }
        return Ok(domains);
    }
    Err(invalid("Source redirect limit reached."))
}
async fn refresh(context: &RuntimeContext, state: &mut State) -> Result<(), AuthorityError> {
    recover_file(
        context,
        state,
        std::path::Path::new("/opt/vpn-appliance-manager"),
    )?;
    let mut tasks = tokio::task::JoinSet::new();
    let enabled: Vec<_> = state
        .policy
        .sources
        .iter()
        .filter(|source| source.enabled && state.policy.enabled)
        .cloned()
        .collect();
    let mut next = enabled.into_iter();
    let mut all_fresh = true;
    let mut unusable = false;
    for _ in 0..4 {
        if let Some(source) = next.next() {
            tasks.spawn(async move {
                let result = fetch(&source).await;
                (source, result)
            });
        }
    }
    while let Some(result) = tasks.join_next().await {
        let (source, fetched) = result.map_err(|_| invalid("A blocking download task failed."))?;
        let prior = state
            .sources
            .iter()
            .find(|item| item.id == source.id && item.url == source.url)
            .cloned();
        let mut status = prior.unwrap_or(SourceStatus {
            id: source.id,
            url: source.url.clone(),
            ..SourceStatus::default()
        });
        status.last_attempt = Some(Utc::now());
        match fetched {
            Ok(domains) => {
                let existing = status
                    .dataset_id
                    .map(|id| context.blocking_dataset(id))
                    .transpose()?;
                if existing.as_ref() != Some(&domains) {
                    status.dataset_id = Some(context.store_blocking_dataset(&domains)?);
                }
                status.domain_count = domains.len();
                status.last_success = Some(Utc::now());
                status.error = None;
                status.stale = false;
            }
            Err(error) => {
                status.error = Some(error.to_string());
                status.stale = true;
                all_fresh = false;
                if status.dataset_id.is_none() {
                    unusable = true;
                }
            }
        }
        state.sources.retain(|item| item.id != source.id);
        state.sources.push(status);
        context.store_blocking_state(state)?;
        if let Some(source) = next.next() {
            tasks.spawn(async move {
                let result = fetch(&source).await;
                (source, result)
            });
        }
    }
    state.sources.retain(|item| {
        state
            .policy
            .sources
            .iter()
            .any(|source| source.id == item.id && source.url == item.url)
    });
    if unusable {
        return Err(invalid(
            "A new or edited source could not be downloaded. The previous DNS blocking rules remain active.",
        ));
    }
    let active = context
        .deployed()?
        .map(|revision| context.historical_configuration(revision))
        .transpose()?;
    let configuration = active.as_ref().unwrap_or(&context.manifest.configuration);
    let domains = effective_domains(
        context,
        &state.policy,
        &state.sources,
        &configuration.dns_blocklist_domains,
    )?;
    let version = dataset_hash(&domains);
    state.dataset_version = Some(version.clone());
    if active.is_some() {
        apply_domains(
            context,
            configuration,
            &domains,
            state,
            std::path::Path::new("/opt/vpn-appliance-manager"),
        )
        .await?;
        state.applied_version = Some(version);
        state.applied_at = Some(Utc::now());
    } else {
        state.error = Some(
            "Blocking data is saved. Deploy this instance once to establish its DNS runtime."
                .into(),
        );
    }
    if all_fresh {
        state.last_success = Some(Utc::now());
    } else {
        state.error = Some("One or more downloads failed. Last successful data for unchanged sources is still in use; review stale sources.".into());
    }
    Ok(())
}
fn dataset_hash(domains: &[String]) -> String {
    let mut hash = Sha256::new();
    for domain in domains {
        hash.update(domain.as_bytes());
        hash.update(b"\n");
    }
    format!("{:x}", hash.finalize())
}
pub(crate) fn effective_domains(
    context: &RuntimeContext,
    policy: &Policy,
    statuses: &[SourceStatus],
    baseline: &[String],
) -> Result<Vec<String>, AuthorityError> {
    if policy.revision == 0 {
        return Ok(baseline.to_vec());
    }
    if !policy.enabled {
        return Ok(vec![]);
    }
    let mut domains = BTreeSet::new();
    let mut bytes = 0_usize;
    for domain in baseline {
        if domains.insert(domain.clone()) {
            bytes += domain.len();
        }
    }
    for source in policy.sources.iter().filter(|source| source.enabled) {
        let status = statuses
            .iter()
            .find(|item| item.id == source.id && item.url == source.url)
            .ok_or_else(|| {
                invalid("An enabled source has no verified dataset. Refresh it before deploying.")
            })?;
        let dataset = status.dataset_id.ok_or_else(|| {
            invalid("An enabled source has no successful download. Refresh it before deploying.")
        })?;
        for domain in context.blocking_dataset(dataset)? {
            if domains.insert(domain.clone()) {
                bytes += domain.len();
            }
            if domains.len() > MAX_DOMAINS || bytes > 64 * 1024 * 1024 {
                return Err(invalid(
                    "Combined blocklists exceed one million domains or 64 MiB of domain names.",
                ));
            }
        }
    }
    Ok(domains.into_iter().collect())
}
fn atomic_file(path: &std::path::Path, contents: &[u8]) -> Result<(), AuthorityError> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Invalid DNS runtime path."))?;
    let temp = parent.join(format!(".vpnctl-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options.open(&temp)?;
        file.write_all(contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok::<_, AuthorityError>(())
    })();
    if result.is_err() && temp.exists() {
        std::fs::remove_file(&temp)?;
    }
    result
}
fn read_runtime_file(path: &std::path::Path) -> Result<Vec<u8>, AuthorityError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err(invalid(
            "DNS runtime file is not a regular file within the 256 MiB recovery limit.",
        ));
    }
    std::fs::read(path).map_err(Into::into)
}
fn recover_file(
    context: &RuntimeContext,
    state: &mut State,
    root: &std::path::Path,
) -> Result<(), AuthorityError> {
    let Some(journal) = &state.apply_journal else {
        return Ok(());
    };
    let directory = root
        .join("instances")
        .join(context.manifest.configuration.instance.id.to_string())
        .join("dns/hosts");
    let backup = directory.join(format!(".vpnctl-{}.previous", journal.id));
    let target = directory.join("blocklist.hosts");
    crate::archive::checked_path(root, &backup)?;
    crate::archive::checked_path(root, &target)?;
    let bytes = read_runtime_file(&backup).map_err(|_| invalid("DNS recovery backup is unavailable. Preserve runtime files and inspect the interrupted update before retrying."))?;
    atomic_file(&target, &bytes)?;
    state.apply_journal = None;
    context.store_blocking_state(state)?;
    std::fs::remove_file(backup)?;
    Ok(())
}
async fn apply_domains(
    context: &RuntimeContext,
    configuration: &vam_authority::manifest::Configuration,
    domains: &[String],
    state: &mut State,
    root: &std::path::Path,
) -> Result<(), AuthorityError> {
    recover_file(context, state, root)?;
    let id = configuration.instance.id;
    let directory = root
        .join("instances")
        .join(id.to_string())
        .join("dns/hosts");
    let target = directory.join("blocklist.hosts");
    crate::archive::checked_path(root, &target)?;
    if !target.is_file() {
        return Err(invalid(
            "No usable DNS runtime exists. Deploy this instance before applying blocking rules.",
        ));
    }
    let version = dataset_hash(domains);
    let journal_id = Uuid::new_v4();
    let marker = format!(
        "vpnctl-{}-{}",
        &version[..16],
        &journal_id.simple().to_string()[..12]
    );
    let mut contents = vam_dns::render_blocklist_hosts(domains);
    // A reserved .invalid sentinel verifies that CoreDNS loaded this dataset,
    // including an otherwise empty dataset when blocking is disabled.
    let verification_zone = if configuration
        .instance
        .dns
        .zone
        .trim_end_matches('.')
        .eq_ignore_ascii_case("invalid")
    {
        "test"
    } else {
        "invalid"
    };
    for attempt in 0..32 {
        contents.push_str(&format!(
            "0.0.0.0 {marker}-{attempt}.{verification_zone}\n:: {marker}-{attempt}.{verification_zone}\n"
        ));
    }
    let backup = directory.join(format!(".vpnctl-{journal_id}.previous"));
    crate::archive::checked_path(root, &backup)?;
    let previous = read_runtime_file(&target)?;
    atomic_file(&backup, &previous)?;
    state.apply_journal = Some(vam_authority::manifest::blocking::ApplyJournal { id: journal_id });
    context.store_blocking_state(state)?;
    let result = async {
        atomic_file(&target, contents.as_bytes())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut attempt = 0;
        loop {
            // Each probe gets a fresh name. A lookup before the hosts reload
            // must not leave later checks trapped in the DNS denial cache.
            let query = format!("{marker}-{attempt}.{verification_zone}"); attempt += 1;
            if dns_marker(root, id, &query).await {
                let private_name = format!("gateway.{}", configuration.instance.dns.zone);
                let gateway = configuration.instance.network.gateway_ipv4.to_string();
                if dns_query(root, id, &private_name, Some(&gateway)).await && dns_query(root, id, "example.com", None).await { break; }
            }
            if attempt >= 32 || tokio::time::Instant::now() >= deadline { return Err(invalid("CoreDNS did not verify the new blocking dataset. Restoring the previous DNS file.")); }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_, AuthorityError>(())
    }.await;
    if let Err(error) = result {
        recover_file(context, state, root).map_err(|_| invalid("DNS rollback failed. The interrupted blocking operation remains pending; inspect its recovery file before retrying."))?;
        return Err(error);
    }
    state.apply_journal = None;
    state.applied_version = Some(version);
    state.applied_at = Some(Utc::now());
    context.store_blocking_state(state)?;
    std::fs::remove_file(backup)?;
    Ok(())
}
async fn dns_marker(root: &std::path::Path, id: Uuid, marker: &str) -> bool {
    dns_query(root, id, marker, Some("0.0.0.0")).await
}
async fn dns_query(root: &std::path::Path, id: Uuid, name: &str, expected: Option<&str>) -> bool {
    let directory = root.join("instances").join(id.to_string());
    let mut command = tokio::process::Command::new("/usr/bin/env");
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("HOME", "/")
        .env(
            "DOCKER_CONFIG",
            "/var/lib/vpn-appliance-manager/control/docker-client",
        )
        .env("USER", "root")
        .env("LC_ALL", "C")
        .args(["docker", "compose", "--project-directory"])
        .arg(directory)
        .args(["exec", "-T", "gateway", "nslookup", name, "127.0.0.1"])
        .kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(5), command.output()).await {
        Ok(Ok(output)) => {
            output.status.success()
                && expected.is_none_or(|value| {
                    String::from_utf8_lossy(&output.stdout)
                        .split_ascii_whitespace()
                        .any(|token| token == value)
                })
        }
        _ => false,
    }
}
/// Reapply the current blocking policy after a deployment, start, or rollback.
/// The caller already holds the authority lock and its operation's pending marker.
pub(crate) async fn apply_cached(
    context: &RuntimeContext,
    configuration: &vam_authority::manifest::Configuration,
    root: &std::path::Path,
) -> Result<(), AuthorityError> {
    let mut state = context.blocking_state()?;
    if state.policy.revision == 0 {
        return Ok(());
    }
    let domains = match effective_domains(
        context,
        &state.policy,
        &state.sources,
        &configuration.dns_blocklist_domains,
    ) {
        Ok(domains) => domains,
        Err(error) => {
            state.applied_version = None;
            state.error = Some(error.to_string());
            context.store_blocking_state(&state)?;
            return Err(error);
        }
    };
    state.dataset_version = Some(dataset_hash(&domains));
    match apply_domains(context, configuration, &domains, &mut state, root).await {
        Ok(()) => {
            state.error = None;
            context.store_blocking_state(&state)
        }
        Err(error) => {
            state.applied_version = None;
            state.error = Some(error.to_string());
            context.store_blocking_state(&state)?;
            Err(error)
        }
    }
}

const SERVICE: &str = "# Managed by VPNCTL dns_blocking_v1\n[Unit]\nDescription=VPNCTL DNS blocking refresh\nAfter=docker.service network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/local/libexec/vam-server blocking-refresh\nTimeoutStartSec=60min\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=/var/lib/vpn-appliance-manager -/opt/vpn-appliance-manager\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=true\nCapabilityBoundingSet=\n";
const TIMER: &str = "# Managed by VPNCTL dns_blocking_v1\n[Unit]\nDescription=Check due VPNCTL DNS blocking refreshes\n[Timer]\nOnBootSec=5min\nOnCalendar=hourly\nRandomizedDelaySec=5min\nPersistent=true\n[Install]\nWantedBy=timers.target\n";
async fn systemctl(arguments: &[&str]) -> Result<(), AuthorityError> {
    let mut command = tokio::process::Command::new("/usr/bin/systemctl");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(arguments)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .map_err(|_| {
            invalid("systemd timer setup timed out. Check systemctl status vpnctl-blocking.timer.")
        })??;
    if !output.status.success() {
        return Err(invalid(
            "systemd timer setup failed. Check systemctl status vpnctl-blocking.timer; manual refresh remains available.",
        ));
    }
    Ok(())
}
async fn install_schedule() -> Result<(), AuthorityError> {
    let root = std::path::Path::new("/etc/systemd/system");
    let service = root.join("vpnctl-blocking.service");
    let timer = root.join("vpnctl-blocking.timer");
    for path in [&service, &timer] {
        crate::archive::checked_path(root, path)?;
    }
    for (path, contents) in [(&service, SERVICE), (&timer, TIMER)] {
        let existing = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(bytes) = &existing
            && !bytes.starts_with(b"# Managed by VPNCTL dns_blocking_v1\n")
        {
            return Err(invalid(
                "An existing systemd unit is not owned by VPNCTL. Preserve it and resolve the naming conflict before enabling scheduling.",
            ));
        }
        if existing.as_deref() != Some(contents.as_bytes()) {
            atomic_file(path, contents.as_bytes())?;
        }
    }
    systemctl(&["daemon-reload"]).await?;
    systemctl(&["enable", "--now", "vpnctl-blocking.timer"]).await
}
fn due(state: &State, now: chrono::DateTime<Utc>) -> bool {
    state.policy.revision > 0
        && state.policy.enabled
        && state.policy.schedule_enabled
        && state.policy.sources.iter().any(|source| source.enabled)
        && state.last_attempt.is_none_or(|last| {
            now.signed_duration_since(last).num_days() >= i64::from(state.policy.interval_days)
        })
}
impl crate::ServerRuntime {
    pub async fn refresh_due_blocklists(&self) -> Result<(), crate::ServerError> {
        let appliance = crate::load_or_create_appliance_id(&self.paths)?;
        crate::manifest_rpc::bind_machine_identity(
            &self.paths,
            &crate::manifest_rpc::read_machine_identity()?,
        )?;
        let store = ManifestStore::open(&self.paths.control_dir(), appliance)?;
        let discovery = store.discover()?;
        if !discovery.errors.is_empty() {
            return Err(invalid(
                "Some authoritative instances could not be read; scheduled refresh aborted.",
            )
            .into());
        }
        let mut failures = 0;
        for manifest in discovery.instances {
            let id = manifest.configuration.instance.id;
            let target = {
                let context = store.runtime_context(id, None)?;
                let state = context.blocking_state()?;
                if let Some(pending) = context.pending_operation()? {
                    context
                        .blocking_intent(pending)?
                        .map(|intent| (pending, intent.action))
                } else if due(&state, Utc::now()) {
                    Some((
                        Uuid::new_v4(),
                        Action::Refresh {
                            expected_revision: state.policy.revision,
                        },
                    ))
                } else {
                    None
                }
            };
            if let Some((request, action)) = target {
                match execute(&store, id, request, action).await {
                    Ok(Reply::Blocking(result)) if result.state.error.is_none() => {}
                    Ok(_) | Err(_) => {
                        failures += 1;
                        eprintln!(
                            "DNS blocking refresh needs attention for instance {id}; inspect its blocking status."
                        );
                    }
                }
            }
        }
        if failures > 0 {
            return Err(invalid("One or more scheduled blocking refreshes need attention. Inspect per-instance blocking status.").into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn policy_is_revision_bound_replayable_and_preserves_desired_state() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let policy = Policy {
            enabled: true,
            ..Policy::default()
        };
        let request = Uuid::new_v4();
        let action = Action::Save {
            expected_revision: 0,
            policy,
        };
        let Reply::Blocking(saved) = execute(&store, id, request, action.clone()).await.unwrap()
        else {
            panic!("blocking response expected")
        };
        assert_eq!(saved.state.policy.revision, 1);
        let Reply::Blocking(replay) = execute(&store, id, request, action).await.unwrap() else {
            panic!("blocking response expected")
        };
        assert_eq!(replay.state.policy.revision, 1);
        assert!(
            execute(
                &store,
                id,
                Uuid::new_v4(),
                Action::Refresh {
                    expected_revision: 0
                }
            )
            .await
            .is_err()
        );
        assert_eq!(store.read(id).unwrap().unwrap().revision, 1);
    }
    #[test]
    fn rejects_unsafe_urls_and_accepts_explicit_http() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.test/list",
            "https://user:secret@example.test/list",
            "https://example.test/list#fragment",
        ] {
            assert!(validate_url(url).is_err());
        }
        assert!(validate_url("http://example.test/list").is_ok());
        assert!(validate_url("https://example.test/list").is_ok());
    }
    #[test]
    fn rejects_metadata_loopback_and_rebinding_addresses_but_supports_lan_sources() {
        for value in [
            "127.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fd00:ec2::254",
        ] {
            assert!(
                !allowed_address(value.parse().unwrap(), false),
                "allowed {value}"
            );
        }
        for value in ["192.168.1.2", "10.0.0.2", "1.1.1.1"] {
            assert!(allowed_address(value.parse().unwrap(), false));
        }
    }
    #[test]
    fn schedule_is_per_instance_and_can_be_disabled() {
        let now = Utc::now();
        let mut state = State::default();
        state.policy.revision = 1;
        state.policy.enabled = true;
        state.policy.sources.push(Source {
            id: Uuid::new_v4(),
            name: "Ads".into(),
            url: "https://example.test/list".into(),
            enabled: true,
        });
        state.last_attempt = Some(now - chrono::Duration::days(6));
        assert!(!due(&state, now));
        state.last_attempt = Some(now - chrono::Duration::days(7));
        assert!(due(&state, now));
        state.policy.schedule_enabled = false;
        assert!(!due(&state, now));
        state.policy.schedule_enabled = true;
        state.policy.enabled = false;
        assert!(!due(&state, now));
    }
    #[tokio::test]
    async fn resumes_an_interruption_between_marker_and_policy_publication() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let request = Uuid::new_v4();
        let action = Action::Save {
            expected_revision: 0,
            policy: Policy::default(),
        };
        let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&action).unwrap()));
        {
            let context = store.runtime_context(id, None).unwrap();
            context
                .record_blocking_intent(
                    request,
                    &vam_authority::manifest::blocking::Intent {
                        action,
                        request_hash: hash,
                    },
                )
                .unwrap();
            context.begin_mutation(request).unwrap();
        }
        let Reply::Blocking(read) = execute(&store, id, Uuid::new_v4(), Action::Read)
            .await
            .unwrap()
        else {
            panic!("blocking reply expected")
        };
        assert_eq!(read.state.pending_request, Some(request));
        let Reply::Blocking(result) = execute(&store, id, request, Action::Resume).await.unwrap()
        else {
            panic!("blocking reply expected")
        };
        assert_eq!(result.state.policy.revision, 1);
        assert!(result.state.pending_request.is_none());
        assert!(
            store
                .runtime_context(id, None)
                .unwrap()
                .pending_operation()
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn recovers_the_exact_prior_dns_file_without_changing_vpn_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let context = store.runtime_context(id, None).unwrap();
        let root = dir.path().canonicalize().unwrap();
        let directory = root
            .join("instances")
            .join(id.to_string())
            .join("dns/hosts");
        std::fs::create_dir_all(&directory).unwrap();
        let journal = Uuid::new_v4();
        let backup = directory.join(format!(".vpnctl-{journal}.previous"));
        atomic_file(&backup, b"0.0.0.0 previous.example.test\n").unwrap();
        atomic_file(
            &directory.join("blocklist.hosts"),
            b"interrupted new contents",
        )
        .unwrap();
        let mut state = State {
            apply_journal: Some(vam_authority::manifest::blocking::ApplyJournal { id: journal }),
            ..State::default()
        };
        recover_file(&context, &mut state, &root).unwrap();
        assert_eq!(
            std::fs::read(directory.join("blocklist.hosts")).unwrap(),
            b"0.0.0.0 previous.example.test\n"
        );
        assert!(state.apply_journal.is_none());
        assert!(!backup.exists());
        assert_eq!(context.manifest.revision, 1);
    }
    #[test]
    fn disabled_policy_preserves_baseline_but_applies_no_blocking_domains() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let context = store.runtime_context(id, None).unwrap();
        let baseline = vec!["baseline.example.test".into()];
        let policy = Policy {
            revision: 1,
            ..Policy::default()
        };
        assert!(
            effective_domains(&context, &policy, &[], &baseline)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            effective_domains(&context, &Policy::default(), &[], &baseline).unwrap(),
            baseline
        );
    }
    #[tokio::test]
    async fn completion_receipt_finishes_publication_without_repeating_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let request = Uuid::new_v4();
        let action = Action::Save {
            expected_revision: 0,
            policy: Policy::default(),
        };
        let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&action).unwrap()));
        {
            let context = store.runtime_context(id, None).unwrap();
            context
                .record_blocking_intent(
                    request,
                    &vam_authority::manifest::blocking::Intent {
                        action,
                        request_hash: hash.clone(),
                    },
                )
                .unwrap();
            context.begin_mutation(request).unwrap();
            let old = State {
                pending_request: Some(request),
                ..State::default()
            };
            context.store_blocking_state(&old).unwrap();
            let mut completed = State::default();
            completed.policy.revision = 1;
            context
                .record_blocking(
                    request,
                    &Receipt {
                        request_hash: hash,
                        state: completed,
                    },
                )
                .unwrap();
        }
        let Reply::Blocking(result) = execute(&store, id, request, Action::Resume).await.unwrap()
        else {
            panic!("blocking reply expected")
        };
        assert_eq!(result.state.policy.revision, 1);
        assert!(result.state.pending_request.is_none());
        let context = store.runtime_context(id, None).unwrap();
        assert_eq!(context.blocking_state().unwrap().policy.revision, 1);
        assert!(context.pending_operation().unwrap().is_none());
    }
    #[tokio::test]
    async fn unchanged_failed_source_reuses_its_last_successful_domains() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let source = Source {
            id: Uuid::new_v4(),
            name: "Previous list".into(),
            url: "http://127.0.0.1:9/list".into(),
            enabled: true,
        };
        let last = Utc::now() - chrono::Duration::days(2);
        {
            let context = store.runtime_context(id, None).unwrap();
            let dataset = context
                .store_blocking_dataset(&["ads.example.test".into()])
                .unwrap();
            let state = State {
                policy: Policy {
                    revision: 1,
                    enabled: true,
                    schedule_enabled: false,
                    sources: vec![source.clone()],
                    ..Policy::default()
                },
                sources: vec![SourceStatus {
                    id: source.id,
                    url: source.url,
                    last_success: Some(last),
                    dataset_id: Some(dataset),
                    domain_count: 1,
                    ..SourceStatus::default()
                }],
                last_success: Some(last),
                applied_version: Some("previously-applied".into()),
                ..State::default()
            };
            context.store_blocking_state(&state).unwrap();
        }
        let Reply::Blocking(result) = execute(
            &store,
            id,
            Uuid::new_v4(),
            Action::Refresh {
                expected_revision: 1,
            },
        )
        .await
        .unwrap() else {
            panic!("blocking reply expected")
        };
        assert!(result.state.sources[0].stale);
        assert_eq!(result.state.last_success, Some(last));
        assert_eq!(
            result.state.applied_version.as_deref(),
            Some("previously-applied")
        );
        assert_eq!(
            result.state.dataset_version,
            Some(dataset_hash(&["ads.example.test".into()]))
        );
    }
    #[test]
    fn policy_and_datasets_do_not_leak_across_instances() {
        use std::collections::BTreeMap;
        use vam_authority::manifest::{Compatibility, SaveRequest};
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let current = store.read(id).unwrap().unwrap();
        let other_id = Uuid::new_v4();
        let mut other = current.configuration.clone();
        other.instance.id = other_id;
        other.instance.endpoint.port = 51821;
        other.instance.network.ipv4_subnet = "10.89.0.0/24".parse().unwrap();
        other.instance.network.gateway_ipv4 = "10.89.0.1".parse().unwrap();
        store
            .save(&SaveRequest {
                compatibility: Compatibility::default(),
                appliance_id: current.appliance_id,
                request_id: Uuid::new_v4(),
                expected_revision: 0,
                configuration: other,
                secrets: BTreeMap::new(),
            })
            .unwrap();
        {
            let context = store.runtime_context(id, None).unwrap();
            let mut state = State::default();
            state.policy.revision = 3;
            context.store_blocking_state(&state).unwrap();
        }
        let context = store.runtime_context(other_id, None).unwrap();
        assert_eq!(context.blocking_state().unwrap().policy.revision, 0);
    }
    fn http_source(response: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        tokio::task::spawn_blocking(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = [0_u8; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            let _ = socket.write_all(&response);
        });
        format!("http://{address}/list")
    }
    #[tokio::test]
    async fn downloads_hosts_and_domain_lists_with_deduplication() {
        let body = "0.0.0.0 ads.example.test\n:: ads.example.test\ntrack.example.test\n# comment\n";
        let url = http_source(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let source = Source {
            id: Uuid::new_v4(),
            name: "Test source".into(),
            url,
            enabled: true,
        };
        assert_eq!(
            fetch_with_policy(&source, true).await.unwrap(),
            vec!["ads.example.test", "track.example.test"]
        );
    }
    #[tokio::test]
    async fn refuses_oversized_and_empty_downloads() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 20971521\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ] {
            let url = http_source(response);
            let source = Source {
                id: Uuid::new_v4(),
                name: "Test source".into(),
                url,
                enabled: true,
            };
            assert!(fetch_with_policy(&source, true).await.is_err());
        }
    }
    #[tokio::test]
    async fn refuses_malformed_text_credential_redirects_and_tls_failures() {
        for (response, tls) in [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\xff".to_vec(), false),
            (b"HTTP/1.1 302 Found\r\nLocation: http://user:password@example.test/list\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), true),
        ] {
            let mut url = http_source(response); if tls { url = url.replacen("http:", "https:", 1); }
            let source = Source { id: Uuid::new_v4(), name: "Invalid source".into(), url, enabled: true };
            assert!(fetch_with_policy(&source, true).await.is_err());
        }
    }
    #[tokio::test]
    async fn changed_source_failure_preserves_the_applied_dataset() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let url = "http://127.0.0.1:9/list".to_owned();
        let policy = Policy {
            enabled: true,
            schedule_enabled: false,
            sources: vec![Source {
                id: Uuid::new_v4(),
                name: "Unavailable".into(),
                url,
                enabled: true,
            }],
            ..Policy::default()
        };
        let Reply::Blocking(reply) = execute(
            &store,
            id,
            Uuid::new_v4(),
            Action::Save {
                expected_revision: 0,
                policy,
            },
        )
        .await
        .unwrap() else {
            panic!("blocking response expected")
        };
        assert!(
            reply
                .state
                .error
                .unwrap()
                .contains("previous DNS blocking rules remain")
        );
        assert!(reply.state.applied_version.is_none());
        assert!(reply.state.sources[0].stale);
    }
    #[test]
    fn datasets_are_sharded_and_recovered_under_the_control_store() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let context = store.runtime_context(id, None).unwrap();
        let domains: Vec<_> = (0..40_001).map(|i| format!("ad{i}.example.test")).collect();
        let dataset = context.store_blocking_dataset(&domains).unwrap();
        assert_eq!(context.blocking_dataset(dataset).unwrap(), domains);
    }
}
