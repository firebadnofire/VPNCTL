use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};

use chrono::{Datelike, NaiveDate};
use thiserror::Error;
use vam_core::{DnsRecord, DnsRecordType};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNS zone is invalid")]
    InvalidZone,
    #[error("record name {0} is outside the private zone")]
    OutsideZone(String),
    #[error("record {0} has an invalid value")]
    InvalidValue(String),
    #[error("record TTL must be between 30 and 86400 seconds")]
    InvalidTtl,
    #[error("duplicate DNS record")]
    Duplicate,
    #[error("a CNAME owner cannot have other record types")]
    CnameConflict,
    #[error("SOA serial sequence exhausted for the day")]
    SerialExhausted,
}

pub fn normalize_zone(zone: &str) -> Result<String, DnsError> {
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if zone.len() > 253 || !zone.contains('.') || !valid_name(&zone) {
        return Err(DnsError::InvalidZone);
    }
    Ok(zone)
}

pub fn validate_records(zone: &str, records: &[DnsRecord]) -> Result<(), DnsError> {
    let zone = normalize_zone(zone)?;
    let mut seen = BTreeSet::new();
    let mut owner_types: HashMap<String, BTreeSet<DnsRecordType>> = HashMap::new();
    for record in records.iter().filter(|record| record.enabled) {
        if !(30..=86_400).contains(&record.ttl) {
            return Err(DnsError::InvalidTtl);
        }
        let owner = canonical_owner(&record.name, &zone)?;
        validate_value(record.record_type, &record.value)?;
        if !seen.insert((
            owner.clone(),
            record.record_type,
            record.value.trim().to_ascii_lowercase(),
        )) {
            return Err(DnsError::Duplicate);
        }
        let existing = owner_types.entry(owner).or_default();
        if (record.record_type == DnsRecordType::Cname && !existing.is_empty())
            || existing.contains(&DnsRecordType::Cname)
        {
            return Err(DnsError::CnameConflict);
        }
        existing.insert(record.record_type);
    }
    if owner_types
        .values()
        .any(|types| types.contains(&DnsRecordType::Cname) && types.len() > 1)
    {
        return Err(DnsError::CnameConflict);
    }
    Ok(())
}

pub fn next_soa_serial(previous: u64, today: NaiveDate) -> Result<u64, DnsError> {
    let today_base = u64::from(today.year_ce().1) * 1_000_000
        + u64::from(today.month()) * 10_000
        + u64::from(today.day()) * 100;
    if previous < today_base {
        return Ok(today_base + 1);
    }
    if previous % 100 >= 99 {
        return Err(DnsError::SerialExhausted);
    }
    Ok(previous + 1)
}

pub fn render_corefile(zone: &str) -> Result<String, DnsError> {
    let zone = normalize_zone(zone)?;
    Ok(format!(
        "{zone} {{\n    errors\n    auto {{\n        directory /etc/coredns/zones db.(.*) {{1}}\n        reload 5s\n    }}\n}}\n\n. {{\n    errors\n    health\n    ready\n    forward . tls://1.1.1.1 tls://1.0.0.1 {{\n        tls_servername one.one.one.one\n        health_check 5s\n        policy round_robin\n    }}\n    cache 300\n}}\n"
    ))
}

pub fn render_zone(
    zone: &str,
    gateway: Ipv4Addr,
    serial: u64,
    records: &[DnsRecord],
) -> Result<String, DnsError> {
    let zone = normalize_zone(zone)?;
    validate_records(&zone, records)?;
    let mut enabled: Vec<_> = records.iter().filter(|record| record.enabled).collect();
    enabled.sort_by_key(|record| {
        (
            record.name.to_ascii_lowercase(),
            record.record_type,
            record.value.to_ascii_lowercase(),
            record.id,
        )
    });
    let mut output = format!(
        "$ORIGIN {zone}.\n$TTL 300\n\n@ IN SOA gateway.{zone}. hostmaster.{zone}. (\n    {serial}\n    3600\n    600\n    86400\n    300\n)\n\n@ IN NS gateway.{zone}.\ngateway IN A {gateway}\n"
    );
    for record in enabled {
        let owner = relative_owner(&record.name, &zone)?;
        let kind = match record.record_type {
            DnsRecordType::A => "A",
            DnsRecordType::Aaaa => "AAAA",
            DnsRecordType::Cname => "CNAME",
            DnsRecordType::Txt => "TXT",
            DnsRecordType::Srv => "SRV",
        };
        let value = render_value(record.record_type, &record.value);
        writeln!(output, "{owner} {} IN {kind} {value}", record.ttl)
            .expect("writing to a String cannot fail");
    }
    Ok(output)
}

fn canonical_owner(name: &str, zone: &str) -> Result<String, DnsError> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let fqdn = if name == "@" || name.is_empty() {
        zone.to_owned()
    } else if name.ends_with(&format!(".{zone}")) || name == zone {
        name.clone()
    } else {
        format!("{name}.{zone}")
    };
    if !valid_name(&fqdn) || !(fqdn == zone || fqdn.ends_with(&format!(".{zone}"))) {
        return Err(DnsError::OutsideZone(name));
    }
    Ok(fqdn)
}

fn relative_owner(name: &str, zone: &str) -> Result<String, DnsError> {
    let owner = canonical_owner(name, zone)?;
    if owner == zone {
        Ok("@".into())
    } else {
        Ok(owner
            .strip_suffix(&format!(".{zone}"))
            .expect("validated zone suffix")
            .to_owned())
    }
}

fn validate_value(record_type: DnsRecordType, value: &str) -> Result<(), DnsError> {
    let value = value.trim();
    let valid = match record_type {
        DnsRecordType::A => value.parse::<Ipv4Addr>().is_ok(),
        DnsRecordType::Aaaa => value.parse::<Ipv6Addr>().is_ok(),
        DnsRecordType::Cname => valid_name(value.trim_end_matches('.')),
        DnsRecordType::Txt => !value.contains(['\n', '\r']) && value.len() <= 255,
        DnsRecordType::Srv => {
            let fields: Vec<_> = value.split_whitespace().collect();
            fields.len() == 4
                && fields[..3].iter().all(|field| field.parse::<u16>().is_ok())
                && valid_name(fields[3].trim_end_matches('.'))
        }
    };
    valid
        .then_some(())
        .ok_or_else(|| DnsError::InvalidValue(value.to_owned()))
}

fn render_value(record_type: DnsRecordType, value: &str) -> String {
    match record_type {
        DnsRecordType::Cname => format!("{}.", value.trim_end_matches('.')),
        DnsRecordType::Txt => format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")),
        DnsRecordType::Srv => {
            let mut fields: Vec<_> = value.split_whitespace().map(str::to_owned).collect();
            if let Some(target) = fields.last_mut() {
                *target = format!("{}.", target.trim_end_matches('.'));
            }
            fields.join(" ")
        }
        _ => value.trim().to_owned(),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '-' || character == '_'
                })
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn record(name: &str, kind: DnsRecordType, value: &str) -> DnsRecord {
        DnsRecord {
            id: Uuid::nil(),
            instance_id: Uuid::nil(),
            name: name.into(),
            record_type: kind,
            value: value.into(),
            ttl: 300,
            enabled: true,
            managed_by_device_id: None,
        }
    }

    #[test]
    fn serial_is_monotonic() {
        let date = NaiveDate::from_ymd_opt(2026, 7, 23).unwrap();
        assert_eq!(next_soa_serial(0, date).unwrap(), 2_026_072_301);
        assert_eq!(next_soa_serial(2_026_072_301, date).unwrap(), 2_026_072_302);
    }

    #[test]
    fn renders_sorted_zone_and_escapes_txt() {
        let records = vec![
            record("z", DnsRecordType::Txt, "hello \"vpn\""),
            record("a", DnsRecordType::A, "10.64.0.2"),
        ];
        let zone = render_zone(
            "vpn.internal",
            "10.64.0.1".parse().unwrap(),
            2_026_072_301,
            &records,
        )
        .unwrap();
        assert!(zone.find("a 300 IN A").unwrap() < zone.find("z 300 IN TXT").unwrap());
        assert!(zone.contains(r#"\"vpn\""#));
    }

    #[test]
    fn rejects_ttl_duplicates_and_cname_conflicts() {
        let mut low_ttl = record("host", DnsRecordType::A, "10.64.0.2");
        low_ttl.ttl = 29;
        assert_eq!(
            validate_records("vpn.internal", &[low_ttl]).unwrap_err(),
            DnsError::InvalidTtl
        );
        let duplicate = record("host", DnsRecordType::A, "10.64.0.2");
        assert_eq!(
            validate_records("vpn.internal", &[duplicate.clone(), duplicate]).unwrap_err(),
            DnsError::Duplicate
        );
        assert_eq!(
            validate_records(
                "vpn.internal",
                &[
                    record("alias", DnsRecordType::Cname, "target.vpn.internal"),
                    record("alias", DnsRecordType::Txt, "conflict"),
                ],
            )
            .unwrap_err(),
            DnsError::CnameConflict
        );
    }

    #[test]
    fn rejects_malformed_record_values_and_serial_rollover() {
        for invalid in [
            record("host", DnsRecordType::A, "999.1.1.1"),
            record("host", DnsRecordType::Aaaa, "not-ipv6"),
            record("service", DnsRecordType::Srv, "zero fields"),
            record("text", DnsRecordType::Txt, "line\nbreak"),
        ] {
            assert!(matches!(
                validate_records("vpn.internal", &[invalid]),
                Err(DnsError::InvalidValue(_))
            ));
        }
        let date = NaiveDate::from_ymd_opt(2026, 7, 23).unwrap();
        assert_eq!(
            next_soa_serial(2_026_072_399, date).unwrap_err(),
            DnsError::SerialExhausted
        );
    }
}
