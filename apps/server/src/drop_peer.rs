//! Removal preserves private material and immutable history. Certificate revocation
//! uses its existing durable operation before the public metadata is removed.
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vam_authority::{
    AuthorityError,
    manifest::{ManifestStore, Operation, PublicIdentity, Reply},
};

#[derive(serde::Serialize, serde::Deserialize)]
struct DropIntent {
    request_hash: String,
}

pub async fn execute(
    store: &ManifestStore,
    request_id: Uuid,
    operation: Operation,
) -> Result<Reply, AuthorityError> {
    let Operation::DropPeer {
        instance_id,
        peer_id,
        expected_revision,
        revoke_request_id,
        confirmed: true,
    } = operation
    else {
        return Err(invalid("Device removal requires explicit confirmation."));
    };
    if request_id == revoke_request_id {
        return Err(invalid("Removal and revocation request IDs must differ."));
    }
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&operation)?));
    let needs_revocation;
    let initial_revision;
    {
        let context = store.runtime_context(instance_id, None)?;
        if let Some(saved) = context.committed_request(request_id, &hash)? {
            if context.pending_operation()? == Some(request_id) {
                context.finish_mutation()?;
            }
            return Ok(Reply::Manifest(Box::new(saved)));
        }
        if let Some(intent) = context.read_record::<DropIntent>(request_id)?
            && intent.request_hash != hash
        {
            return Err(invalid(
                "Device removal request ID reused with different content.",
            ));
        }
        let revocation = store_revocation_hash(instance_id, peer_id, expected_revision)?;
        let revoked = context.committed_request(revoke_request_id, &revocation)?;
        let allowed_revision = revoked
            .as_ref()
            .map_or(expected_revision, |item| item.revision);
        initial_revision = allowed_revision;
        if context.manifest.revision != allowed_revision {
            if revoked.is_some() {
                return Err(invalid(
                    "Certificate revoked; device removal incomplete. The server has newer changes. Review the current device before confirming a new removal request.",
                ));
            }
            return Err(AuthorityError::RevisionConflict {
                expected: allowed_revision,
                actual: context.manifest.revision,
            });
        }
        let peer = context
            .manifest
            .configuration
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .ok_or(AuthorityError::NotFound)?;
        needs_revocation = peer.enabled
            && matches!(
                peer.identity,
                PublicIdentity::Openvpn { .. } | PublicIdentity::Ikev2 { .. }
            );
        if context
            .pending_operation()?
            .is_some_and(|id| id != revoke_request_id)
        {
            return Err(invalid(
                "Resolve the interrupted operation before removing this device.",
            ));
        }
        context.record(
            request_id,
            &DropIntent {
                request_hash: hash.clone(),
            },
        )?;
    }
    let revision = if needs_revocation {
        let reply = crate::enrollment::mutate(
            store,
            revoke_request_id,
            Operation::RevokePeer {
                instance_id,
                peer_id,
                expected_revision,
                confirmed: true,
            },
        )
        .await?;
        let saved = match reply {
            Reply::Manifest(saved) => saved,
            Reply::OperationFailure(error) => {
                return Err(invalid(&format!(
                    "Certificate revocation did not complete: {} Inspect the operation outcome before retrying.",
                    error.message
                )));
            }
            _ => return Err(invalid("Unexpected certificate revocation response.")),
        };
        saved.revision
    } else {
        let pending = {
            let context = store.runtime_context(instance_id, Some(initial_revision))?;
            context.pending_operation()?
        };
        if pending == Some(revoke_request_id) {
            crate::enrollment::mutate(
                store,
                revoke_request_id,
                Operation::RevokePeer {
                    instance_id,
                    peer_id,
                    expected_revision,
                    confirmed: true,
                },
            )
            .await?;
        }
        initial_revision
    };
    let result = remove_metadata(store, instance_id, peer_id, revision, request_id, &hash);
    if needs_revocation {
        result.map_err(|error| invalid(&format!("Certificate revoked; device removal incomplete. Retry the same removal request. {error}")))
    } else {
        result
    }
}
fn store_revocation_hash(
    instance_id: Uuid,
    peer_id: Uuid,
    expected_revision: u64,
) -> Result<String, AuthorityError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&Operation::RevokePeer {
            instance_id,
            peer_id,
            expected_revision,
            confirmed: true
        })?)
    ))
}
fn remove_metadata(
    store: &ManifestStore,
    instance_id: Uuid,
    peer_id: Uuid,
    revision: u64,
    request_id: Uuid,
    hash: &str,
) -> Result<Reply, AuthorityError> {
    let context = store.runtime_context(instance_id, Some(revision))?;
    if context.pending_operation()?.is_some() {
        return Err(invalid(
            "Resolve the interrupted operation before removing this device.",
        ));
    }
    let mut configuration = context.manifest.configuration.clone();
    let peer = configuration
        .peers
        .iter()
        .find(|peer| peer.id == peer_id)
        .ok_or(AuthorityError::NotFound)?;
    if peer.enabled
        && matches!(
            peer.identity,
            PublicIdentity::Openvpn { .. } | PublicIdentity::Ikev2 { .. }
        )
    {
        return Err(invalid(
            "Revoke this certificate before removing device metadata.",
        ));
    }
    configuration.peers.retain(|peer| peer.id != peer_id);
    configuration
        .dns_records
        .retain(|record| record.managed_by_device_id != Some(peer_id));
    vam_application::validate_remote_configuration(&configuration)
        .map_err(|error| invalid(&error.message))?;
    let saved = context.commit_configuration(configuration, request_id, hash)?;
    Ok(Reply::Manifest(Box::new(saved)))
}
fn invalid(message: &str) -> AuthorityError {
    AuthorityError::InvalidState(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vam_authority::manifest::{Peer, PublicIdentity};
    #[test]
    fn old_runtime_backups_cannot_undo_revocation_after_metadata_is_dropped() {
        use std::collections::BTreeMap;
        use vam_authority::manifest::{Compatibility, SaveRequest};
        let dir = tempfile::tempdir().unwrap();
        let (store, fixture_id) = crate::test_support::fixture(dir.path());
        let original = store.read(fixture_id).unwrap().unwrap();
        let id = Uuid::new_v4();
        let mut configuration = original.configuration.clone();
        configuration.instance.id = id;
        configuration.instance.backend = vam_core::VpnBackendKind::OpenVpn;
        configuration.instance.backend_settings = vam_core::BackendSettings::defaults_for(
            vam_core::VpnBackendKind::OpenVpn,
            "vpn.example.test",
        );
        configuration.instance.endpoint.port = 1194;
        configuration.instance.network.ipv4_subnet = "10.89.0.0/24".parse().unwrap();
        configuration.instance.network.gateway_ipv4 = "10.89.0.1".parse().unwrap();
        store
            .save(&SaveRequest {
                compatibility: Compatibility::default(),
                appliance_id: original.appliance_id,
                request_id: Uuid::new_v4(),
                expected_revision: 0,
                configuration,
                secrets: BTreeMap::new(),
            })
            .unwrap();
        for stage in 0..3 {
            let context = store.runtime_context(id, None).unwrap();
            let mut configuration = context.manifest.configuration.clone();
            if stage == 0 {
                configuration.peers.push(Peer {
                    id: Uuid::new_v4(),
                    user_id: None,
                    display_name: "Certificate client".into(),
                    ipv4_address: Some("10.89.0.2".parse().unwrap()),
                    ipv6_address: None,
                    dns_name: None,
                    enabled: true,
                    identity: PublicIdentity::Openvpn {
                        common_name: "test-client".into(),
                        certificate_serial: Some("01".into()),
                    },
                    created_at: chrono::Utc::now(),
                });
            } else if stage == 1 {
                configuration.peers[0].enabled = false;
            } else {
                configuration.peers.clear();
            }
            context
                .commit_configuration(configuration, Uuid::new_v4(), "fixture")
                .unwrap();
        }
        let context = store.runtime_context(id, None).unwrap();
        assert!(context.validate_certificate_backup_revision(1).is_err());
        assert!(context.validate_certificate_backup_revision(2).is_err());
        assert!(context.validate_certificate_backup_revision(4).is_ok());
    }
    #[tokio::test]
    async fn removal_is_scoped_revision_bound_and_replayable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, id) = crate::test_support::fixture(dir.path());
        let peer_id = Uuid::new_v4();
        {
            let context = store.runtime_context(id, Some(1)).unwrap();
            let mut config = context.manifest.configuration.clone();
            config.peers.push(Peer {
                id: peer_id,
                user_id: None,
                display_name: "phone".into(),
                ipv4_address: Some("10.88.0.2".parse().unwrap()),
                ipv6_address: None,
                dns_name: Some("phone.vpn.internal".into()),
                enabled: true,
                identity: PublicIdentity::Wireguard {
                    public_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".into(),
                    preshared_key: None,
                },
                created_at: chrono::Utc::now(),
            });
            for managed in [Some(peer_id), None] {
                config.dns_records.push(vam_core::DnsRecord {
                    id: Uuid::new_v4(),
                    instance_id: id,
                    name: if managed.is_some() {
                        "phone.vpn.internal"
                    } else {
                        "other.vpn.internal"
                    }
                    .into(),
                    record_type: vam_core::DnsRecordType::A,
                    value: "10.88.0.2".into(),
                    ttl: 300,
                    enabled: true,
                    managed_by_device_id: managed,
                });
            }
            context
                .commit_configuration(config, Uuid::new_v4(), "fixture")
                .unwrap();
        }
        let operation = Operation::DropPeer {
            instance_id: id,
            peer_id,
            expected_revision: 2,
            revoke_request_id: Uuid::new_v4(),
            confirmed: true,
        };
        let request_id = Uuid::new_v4();
        let mut stale = operation.clone();
        if let Operation::DropPeer {
            expected_revision, ..
        } = &mut stale
        {
            *expected_revision = 1;
        }
        assert!(execute(&store, Uuid::new_v4(), stale).await.is_err());
        let Reply::Manifest(saved) = execute(&store, request_id, operation.clone())
            .await
            .unwrap()
        else {
            panic!("manifest expected")
        };
        assert!(saved.configuration.peers.is_empty());
        assert_eq!(saved.configuration.dns_records.len(), 1);
        assert!(
            saved.configuration.dns_records[0]
                .managed_by_device_id
                .is_none()
        );
        assert_eq!(saved.revision, 3);
        let Reply::Manifest(replay) = execute(&store, request_id, operation).await.unwrap() else {
            panic!("manifest expected")
        };
        assert_eq!(replay.revision, 3);
        assert_eq!(store.history(id).unwrap().len(), 3);
    }
}
