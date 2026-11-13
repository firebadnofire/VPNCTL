//! Server-owned DNS policy and bounded, immutable dataset shards. All methods
//! run under the existing host-wide mutation lock held by `RuntimeContext`.
use super::{RuntimeContext, invalid, optional_json, private_directory, read_json, replace_json};
use crate::AuthorityError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

pub const CAPABILITY: &str = "dns_blocking_v1";
pub const MAX_DOMAINS: usize = 1_000_000;
const SHARD_SIZE: usize = 20_000;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: u64,
    pub enabled: bool,
    pub schedule_enabled: bool,
    pub interval_days: u16,
    pub sources: Vec<Source>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            revision: 0,
            enabled: false,
            schedule_enabled: true,
            interval_days: 7,
            sources: vec![],
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceStatus {
    pub id: Uuid,
    pub url: String,
    pub last_attempt: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub domain_count: usize,
    pub error: Option<String>,
    pub stale: bool,
    pub dataset_id: Option<Uuid>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyJournal {
    pub id: Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default)]
    pub apply_journal: Option<ApplyJournal>,
    pub policy: Policy,
    pub sources: Vec<SourceStatus>,
    pub last_attempt: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub dataset_version: Option<String>,
    pub applied_version: Option<String>,
    pub applied_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub pending_request: Option<Uuid>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {
    pub state: State,
    pub scheduler_available: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Resume,
    Read,
    Save {
        expected_revision: u64,
        policy: Policy,
    },
    Refresh {
        expected_revision: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub request_hash: String,
    pub state: State,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub action: Action,
    pub request_hash: String,
}
#[derive(Serialize, Deserialize)]
struct Dataset {
    shards: usize,
    count: usize,
}
impl RuntimeContext {
    fn blocking_dir(&self) -> Result<PathBuf, AuthorityError> {
        let directory = self
            .directory
            .parent()
            .ok_or_else(|| invalid("invalid blocking storage path"))?
            .join("blocking");
        private_directory(&directory)?;
        Ok(directory)
    }
    pub fn blocking_state(&self) -> Result<State, AuthorityError> {
        Ok(optional_json(&self.blocking_dir()?.join("state.json"))?.unwrap_or_default())
    }
    pub fn store_blocking_state(&self, state: &State) -> Result<(), AuthorityError> {
        replace_json(&self.blocking_dir()?.join("state.json"), state)
    }
    pub fn blocking_intent(&self, request: Uuid) -> Result<Option<Intent>, AuthorityError> {
        optional_json(&self.blocking_dir()?.join(format!("intent-{request}.json")))
    }
    pub fn record_blocking_intent(
        &self,
        request: Uuid,
        intent: &Intent,
    ) -> Result<(), AuthorityError> {
        replace_json(
            &self.blocking_dir()?.join(format!("intent-{request}.json")),
            intent,
        )
    }
    pub fn blocking_receipt(&self, request: Uuid) -> Result<Option<Receipt>, AuthorityError> {
        optional_json(&self.blocking_dir()?.join(format!("receipt-{request}.json")))
    }
    pub fn record_blocking(&self, request: Uuid, receipt: &Receipt) -> Result<(), AuthorityError> {
        replace_json(
            &self.blocking_dir()?.join(format!("receipt-{request}.json")),
            receipt,
        )
    }
    pub fn store_blocking_dataset(&self, domains: &[String]) -> Result<Uuid, AuthorityError> {
        if domains.len() > MAX_DOMAINS {
            return Err(invalid("DNS blocking exceeds one million unique domains."));
        }
        let id = Uuid::new_v4();
        let directory = self.blocking_dir()?.join(id.to_string());
        private_directory(&directory)?;
        for (index, shard) in domains.chunks(SHARD_SIZE).enumerate() {
            replace_json(&directory.join(format!("{index}.json")), &shard)?;
        }
        replace_json(
            &directory.join("index.json"),
            &Dataset {
                shards: domains.len().div_ceil(SHARD_SIZE),
                count: domains.len(),
            },
        )?;
        Ok(id)
    }
    pub fn blocking_dataset(&self, id: Uuid) -> Result<Vec<String>, AuthorityError> {
        let directory = self.blocking_dir()?.join(id.to_string());
        super::reject_symlink(&directory)?;
        let index: Dataset = read_json(&directory.join("index.json"))?;
        if index.count > MAX_DOMAINS || index.shards != index.count.div_ceil(SHARD_SIZE) {
            return Err(invalid("Invalid DNS dataset index."));
        }
        let mut domains = Vec::with_capacity(index.count);
        for shard in 0..index.shards {
            let values: Vec<String> = read_json(&directory.join(format!("{shard}.json")))?;
            if values.len() > SHARD_SIZE {
                return Err(invalid("Invalid DNS dataset shard."));
            }
            domains.extend(values);
        }
        if domains.len() != index.count {
            return Err(invalid("Incomplete DNS dataset."));
        }
        Ok(domains)
    }
}
