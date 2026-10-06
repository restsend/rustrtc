use crate::platform::time::Instant;
use crate::prelude::*;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Debug, Clone)]
pub struct StatsEntry {
    pub id: StatsId,
    pub kind: StatsKind,
    pub timestamp: Instant,
    pub values: BTreeMap<String, Value>,
}

impl StatsEntry {
    pub fn new(id: StatsId, kind: StatsKind) -> Self {
        Self {
            id,
            kind,
            timestamp: Instant::now(),
            values: BTreeMap::new(),
        }
    }

    pub fn with_value(mut self, key: impl Into<String>, value: Value) -> Self {
        self.values.insert(key.into(), value);
        self
    }
}

impl core::fmt::Display for StatsEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

#[derive(Debug, Clone)]
pub struct StatsReport {
    pub collected_at: Instant,
    pub entries: Vec<StatsEntry>,
}

impl StatsReport {
    pub fn new(entries: Vec<StatsEntry>) -> Self {
        Self {
            collected_at: Instant::now(),
            entries,
        }
    }

    pub fn merge(mut self, mut other: StatsReport) -> Self {
        self.entries.append(&mut other.entries);
        self.collected_at = self.collected_at.max(other.collected_at);
        self
    }
}

impl core::fmt::Display for StatsReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StatsReport(len={})", self.entries.len())?;
        for entry in &self.entries {
            write!(f, " {}", entry)?;
        }
        Ok(())
    }
}

/// Sync collect on purpose: implementations read atomic counters, so no
/// awaiting is needed — and a sync trait stays dyn-compatible without
/// async_trait, keeping it available to the no_std build.
pub trait StatsProvider: Send + Sync {
    fn collect(&self) -> RtcResult<Vec<StatsEntry>>;
}

pub fn gather_once(providers: &[Arc<DynProvider>]) -> RtcResult<StatsReport> {
    let mut entries = Vec::new();
    for provider in providers {
        entries.extend(provider.collect()?);
    }
    Ok(StatsReport::new(entries))
}
