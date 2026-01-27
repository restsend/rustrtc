use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use crate::errors::RtcResult;

pub type DynProvider = dyn StatsProvider + Send + Sync + 'static;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StatsId(String);

impl StatsId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StatsKind {
    InboundRtp,
    OutboundRtp,
    RemoteInboundRtp,
    RemoteOutboundRtp,
    Transport,
    IceCandidatePair,
    DataChannel,
    MediaSource,
    MediaSink,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsEntry {
    pub id: StatsId,
    pub kind: StatsKind,
    pub timestamp: SystemTime,
    pub values: BTreeMap<String, Value>,
}

impl StatsEntry {
    pub fn new(id: StatsId, kind: StatsKind) -> Self {
        Self {
            id,
            kind,
            timestamp: SystemTime::now(),
            values: BTreeMap::new(),
        }
    }

    pub fn with_value(mut self, key: impl Into<String>, value: Value) -> Self {
        self.values.insert(key.into(), value);
        self
    }
}

impl std::fmt::Display for StatsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}/{}]", self.kind, self.id.0)?;
        for (k, v) in &self.values {
            // Attempt to display strings without quotes for cleaner logs, fallback to standard display
            if let Some(s) = v.as_str() {
                write!(f, " {}={}", k, s)?;
            } else {
                write!(f, " {}={}", k, v)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsReport {
    pub collected_at: SystemTime,
    pub entries: Vec<StatsEntry>,
}

impl StatsReport {
    pub fn new(entries: Vec<StatsEntry>) -> Self {
        Self {
            collected_at: SystemTime::now(),
            entries,
        }
    }

    pub fn merge(mut self, mut other: StatsReport) -> Self {
        self.entries.append(&mut other.entries);
        self.collected_at = self.collected_at.max(other.collected_at);
        self
    }
}

impl std::fmt::Display for StatsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatsReport(len={})", self.entries.len())?;
        for entry in &self.entries {
            write!(f, " {}", entry)?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait StatsProvider: Send + Sync {
    async fn collect(&self) -> RtcResult<Vec<StatsEntry>>;
}

pub async fn gather_once(providers: &[Arc<DynProvider>]) -> RtcResult<StatsReport> {
    let mut entries = Vec::new();
    for provider in providers {
        entries.extend(provider.collect().await?);
    }
    Ok(StatsReport::new(entries))
}
