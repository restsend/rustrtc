//! UPnP IGD (Internet Gateway Device) support for ICE
//!
//! This module provides port mapping functionality using UPnP IGD protocol.
//! It allows direct peer-to-peer connections through NAT by mapping external
//! ports to internal addresses.

use crate::transports::ice::IceCandidate;
use anyhow::{Result, anyhow};
use igd::aio::Gateway;
use igd::PortMappingProtocol;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Default lease duration for UPnP port mappings in seconds
pub const DEFAULT_LEASE_DURATION: u32 = 3600;

/// Minimum recommended lease duration to avoid frequent renewals
pub const MIN_LEASE_DURATION: u32 = 300;

/// Maximum lease duration (many routers cap at 24 hours)
pub const MAX_LEASE_DURATION: u32 = 86400;

/// Default timeout for UPnP discovery (2 seconds to avoid blocking RTP setup)
pub const DEFAULT_UPNP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// UPnP IGD port mapping entry
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub external_port: u16,
    pub internal_addr: SocketAddr,
    pub lease_duration: u32,
    pub description: String,
    pub created_at: std::time::Instant,
}

impl PortMapping {
    /// Check if the mapping is expired or about to expire (within 60 seconds)
    pub fn is_expired_or_stale(&self) -> bool {
        let elapsed = self.created_at.elapsed().as_secs() as u32;
        // Consider stale 60 seconds before actual expiry
        elapsed + 60 >= self.lease_duration
    }

    /// Calculate remaining lifetime in seconds
    pub fn remaining_lifetime(&self) -> u32 {
        let elapsed = self.created_at.elapsed().as_secs() as u32;
        self.lease_duration.saturating_sub(elapsed)
    }
}

/// UPnP IGD port mapping manager
///
/// Manages port mappings through UPnP-enabled routers. Each mapping
/// associates an external port with an internal address, allowing
/// incoming connections from the internet.
#[derive(Debug, Clone)]
pub struct UpnpPortMapper {
    gateway: Option<Gateway>,
    mappings: Arc<Mutex<HashMap<u16, PortMapping>>>,
    /// Local address to use for mappings
    pub local_addr: SocketAddr,
    /// Default lease duration for new mappings
    pub default_lease_duration: u32,
    /// Whether UPnP is enabled
    enabled: bool,
}

impl UpnpPortMapper {
    /// Create a new UPnP port mapper for the given local address
    ///
    /// The mapper starts in a disabled state until `discover()` is called.
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            gateway: None,
            mappings: Arc::new(Mutex::new(HashMap::new())),
            local_addr,
            default_lease_duration: DEFAULT_LEASE_DURATION,
            enabled: true,
        }
    }

    /// Create a new UPnP port mapper with custom lease duration
    pub fn with_lease_duration(local_addr: SocketAddr, lease_duration: u32) -> Self {
        let lease_duration = lease_duration.clamp(MIN_LEASE_DURATION, MAX_LEASE_DURATION);
        Self {
            gateway: None,
            mappings: Arc::new(Mutex::new(HashMap::new())),
            local_addr,
            default_lease_duration: lease_duration,
            enabled: true,
        }
    }

    /// Disable UPnP functionality
    pub fn disable(&mut self) {
        self.enabled = false;
        self.gateway = None;
    }

    /// Enable UPnP functionality
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Check if UPnP is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Discover and connect to a UPnP IGD gateway
    ///
    /// This method searches for UPnP IGD devices on the local network
    /// and attempts to connect to the first one found.
    /// Uses DEFAULT_UPNP_DISCOVERY_TIMEOUT (2 seconds) to avoid blocking.
    pub async fn discover(&mut self) -> Result<()> {
        self.discover_with_timeout(DEFAULT_UPNP_DISCOVERY_TIMEOUT).await
    }

    /// Discover and connect to a UPnP IGD gateway with custom timeout
    ///
    /// This method searches for UPnP IGD devices on the local network
    /// and attempts to connect to the first one found.
    pub async fn discover_with_timeout(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<()> {
        if !self.enabled {
            return Err(anyhow!("UPnP is disabled"));
        }

        // Skip if bound to loopback (can't map loopback)
        if self.local_addr.ip().is_loopback() {
            return Err(anyhow!("Cannot map loopback address"));
        }

        trace!(
            "Starting UPnP gateway discovery (timeout: {:?})",
            timeout_duration
        );

        let gateway = timeout(timeout_duration, igd::aio::search_gateway(Default::default()))
            .await
            .map_err(|_| {
                anyhow!(
                    "UPnP gateway discovery timed out after {:?}",
                    timeout_duration
                )
            })?
            .map_err(|e| anyhow!("UPnP gateway discovery failed: {}", e))?;

        debug!("Found UPnP gateway");
        self.gateway = Some(gateway);
        Ok(())
    }

    /// Check if a gateway has been discovered
    pub fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }

    /// Get the external IP address from the gateway
    ///
    /// Returns the public IP address as seen by the router.
    pub async fn get_external_ip(&self) -> Result<Ipv4Addr> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| anyhow!("No UPnP gateway available"))?;

        let ip = gateway
            .get_external_ip()
            .await
            .map_err(|e| anyhow!("Failed to get external IP: {}", e))?;

        Ok(ip)
    }

    /// Add a port mapping
    ///
    /// Maps an external port to the local address. If external_port is 0,
    /// a random available port will be chosen by the router.
    ///
    /// Returns the external address (IP:port) that was mapped.
    pub async fn add_mapping(&self, external_port: u16) -> Result<SocketAddr> {
        if !self.enabled {
            return Err(anyhow!("UPnP is disabled"));
        }

        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| anyhow!("No UPnP gateway available, call discover() first"))?;

        // Get external IP first
        let external_ip = self.get_external_ip().await?;

        // Determine which port to request
        let requested_port = if external_port == 0 {
            // Try to use the same port as local for simplicity
            self.local_addr.port()
        } else {
            external_port
        };

        let description = format!("rustrtc-{}", self.local_addr.port());

        // Add the port mapping
        let local_ip = match self.local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 not supported for UPnP IGD")),
        };

        trace!(
            "Adding UPnP port mapping: {}:{} -> {}:{}",
            external_ip,
            requested_port,
            local_ip,
            self.local_addr.port()
        );

        let internal_sock_addr = SocketAddrV4::new(local_ip, self.local_addr.port());

        match gateway
            .add_port(
                PortMappingProtocol::UDP,
                requested_port,
                internal_sock_addr,
                self.default_lease_duration,
                &description,
            )
            .await
        {
            Ok(()) => {
                let external_addr = SocketAddr::new(IpAddr::V4(external_ip), requested_port);

                let mapping = PortMapping {
                    external_port: requested_port,
                    internal_addr: self.local_addr,
                    lease_duration: self.default_lease_duration,
                    description,
                    created_at: std::time::Instant::now(),
                };

                self.mappings.lock().await.insert(requested_port, mapping);

                debug!(
                    "UPnP port mapping added: {} -> {}",
                    external_addr, self.local_addr
                );

                Ok(external_addr)
            }
            Err(e) => {
                // If the requested port is taken, try with port 0 (random)
                if external_port != 0 && requested_port != 0 {
                    warn!(
                        "Port {} is taken, trying random port: {}",
                        requested_port, e
                    );
                    // Avoid recursion by manually trying a random port
                    self.add_mapping_random_port(gateway, external_ip, local_ip).await
                } else {
                    Err(anyhow!("Failed to add UPnP port mapping: {}", e))
                }
            }
        }
    }

    /// Helper to add mapping with random port - avoids recursion
    async fn add_mapping_random_port(
        &self,
        gateway: &Gateway,
        external_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
    ) -> Result<SocketAddr> {
        // Try ports in a range
        for port in 10000..=65535u16 {
            let description = format!("rustrtc-{}", self.local_addr.port());
            let internal_sock_addr = SocketAddrV4::new(local_ip, self.local_addr.port());

            match gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    port,
                    internal_sock_addr,
                    self.default_lease_duration,
                    &description,
                )
                .await
            {
                Ok(()) => {
                    let external_addr = SocketAddr::new(IpAddr::V4(external_ip), port);

                    let mapping = PortMapping {
                        external_port: port,
                        internal_addr: self.local_addr,
                        lease_duration: self.default_lease_duration,
                        description,
                        created_at: std::time::Instant::now(),
                    };

                    self.mappings.lock().await.insert(port, mapping);

                    debug!(
                        "UPnP port mapping added (random port): {} -> {}",
                        external_addr, self.local_addr
                    );

                    return Ok(external_addr);
                }
                Err(_) => continue,
            }
        }
        Err(anyhow!("Failed to find available port for UPnP mapping"))
    }

    /// Remove a specific port mapping
    ///
    /// Removes the mapping for the given external port.
    pub async fn remove_mapping(&self, external_port: u16) -> Result<()> {
        let gateway = match &self.gateway {
            Some(g) => g,
            None => {
                // Just remove from local tracking if no gateway
                self.mappings.lock().await.remove(&external_port);
                return Ok(());
            }
        };

        gateway
            .remove_port(PortMappingProtocol::UDP, external_port)
            .await
            .map_err(|e| anyhow!("Failed to remove UPnP mapping: {}", e))?;

        self.mappings.lock().await.remove(&external_port);

        debug!("UPnP port mapping removed: {}", external_port);
        Ok(())
    }

    /// Remove all port mappings created by this mapper
    pub async fn cleanup(&self) -> Result<()> {
        let mappings = self.mappings.lock().await.clone();
        let mut last_error = None;

        for (port, _) in mappings {
            if let Err(e) = self.remove_mapping(port).await {
                warn!("Failed to remove UPnP mapping for port {}: {}", port, e);
                last_error = Some(e);
            }
        }

        match last_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Get the number of active mappings
    pub async fn mapping_count(&self) -> usize {
        self.mappings.lock().await.len()
    }

    /// Check if a mapping exists for the given external port
    pub async fn has_mapping(&self, external_port: u16) -> bool {
        self.mappings.lock().await.contains_key(&external_port)
    }

    /// Get all current mappings
    pub async fn get_mappings(&self) -> HashMap<u16, PortMapping> {
        self.mappings.lock().await.clone()
    }

    /// Renew a mapping if it's about to expire
    ///
    /// Returns true if the mapping was renewed, false if it doesn't exist
    /// or doesn't need renewal yet.
    pub async fn renew_mapping(&self, external_port: u16) -> Result<bool> {
        let needs_renewal = {
            let mappings = self.mappings.lock().await;
            match mappings.get(&external_port) {
                Some(mapping) if mapping.is_expired_or_stale() => true,
                Some(_) => return Ok(false), // Exists but doesn't need renewal
                None => return Ok(false),    // Doesn't exist
            }
        };

        if !needs_renewal {
            return Ok(false);
        }

        // Remove old mapping and add new one
        let _ = self.remove_mapping(external_port).await;
        self.add_mapping(external_port).await?;

        debug!("Renewed UPnP mapping for port {}", external_port);
        Ok(true)
    }

    /// Renew all stale mappings
    ///
    /// Returns the number of mappings that were renewed.
    pub async fn renew_all_stale(&self) -> Result<usize> {
        let ports_to_renew: Vec<u16> = {
            let mappings = self.mappings.lock().await;
            mappings
                .values()
                .filter(|m| m.is_expired_or_stale())
                .map(|m| m.external_port)
                .collect()
        };

        let mut renewed = 0;
        for port in ports_to_renew {
            if self.renew_mapping(port).await? {
                renewed += 1;
            }
        }

        Ok(renewed)
    }

    /// Create an ICE server reflexive candidate from a port mapping
    ///
    /// This creates a candidate representing the external address that
    /// peers can use to connect to this host through the NAT.
    pub async fn create_candidate(&self) -> Result<IceCandidate> {
        let mappings = self.mappings.lock().await;

        // Find the first valid mapping
        let mapping = mappings
            .values()
            .next()
            .ok_or_else(|| anyhow!("No UPnP mappings available"))?;

        let external_addr = SocketAddr::new(
            IpAddr::V4(self.get_external_ip().await?),
            mapping.external_port,
        );

        // Create a server reflexive candidate
        Ok(IceCandidate::server_reflexive(
            mapping.internal_addr,
            external_addr,
            1, // component
        ))
    }
}

/// Try to create a UPnP mapped candidate for a local socket address
///
/// This is a convenience function that performs the full UPnP workflow:
/// 1. Discover the gateway
/// 2. Add a port mapping
/// 3. Create an ICE candidate
///
/// Returns None if UPnP is not available or fails.
pub async fn try_create_upnp_candidate(local_addr: SocketAddr) -> Option<IceCandidate> {
    // Skip loopback addresses
    if local_addr.ip().is_loopback() {
        return None;
    }

    let mut mapper = UpnpPortMapper::new(local_addr);

    // Try to discover gateway
    if let Err(e) = mapper.discover().await {
        trace!("UPnP discovery failed for {}: {}", local_addr, e);
        return None;
    }

    // Try to add mapping
    let external_addr = match mapper.add_mapping(0).await {
        Ok(addr) => addr,
        Err(e) => {
            debug!("UPnP mapping failed for {}: {}", local_addr, e);
            return None;
        }
    };

    // Create the candidate
    let candidate = IceCandidate::server_reflexive(local_addr, external_addr, 1);

    debug!(
        "Created UPnP candidate: {} -> {}",
        local_addr, external_addr
    );

    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_mapping_expiry() {
        // Create a mapping with 70 second lease (must be > 60 for is_expired_or_stale test)
        let mapping = PortMapping {
            external_port: 12345,
            internal_addr: "192.168.1.100:5000".parse().unwrap(),
            lease_duration: 70,
            description: "test".to_string(),
            created_at: std::time::Instant::now(),
        };

        // Should not be expired immediately (70 > 60)
        assert!(!mapping.is_expired_or_stale());
        
        // Verify remaining lifetime is close to 70
        let remaining = mapping.remaining_lifetime();
        assert!(remaining >= 69 && remaining <= 70);
    }

    #[test]
    fn test_port_mapping_remaining_lifetime() {
        let mapping = PortMapping {
            external_port: 12345,
            internal_addr: "192.168.1.100:5000".parse().unwrap(),
            lease_duration: 60,
            description: "test".to_string(),
            created_at: std::time::Instant::now(),
        };

        // Should have close to 60 seconds remaining
        let remaining = mapping.remaining_lifetime();
        assert!(remaining > 55 && remaining <= 60);

        // After sleeping, remaining should decrease
        std::thread::sleep(std::time::Duration::from_millis(100));
        let new_remaining = mapping.remaining_lifetime();
        assert!(new_remaining <= remaining, "remaining={}, new_remaining={}", remaining, new_remaining);
    }

    #[test]
    fn test_upnp_mapper_creation() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mapper = UpnpPortMapper::new(addr);

        assert!(mapper.is_enabled());
        assert!(!mapper.has_gateway());
        assert_eq!(mapper.local_addr, addr);
    }

    #[test]
    fn test_upnp_mapper_disable_enable() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mut mapper = UpnpPortMapper::new(addr);

        assert!(mapper.is_enabled());

        mapper.disable();
        assert!(!mapper.is_enabled());
        assert!(mapper.gateway.is_none());

        mapper.enable();
        assert!(mapper.is_enabled());
    }

    #[test]
    fn test_upnp_mapper_custom_lease() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

        // Test clamping to minimum
        let mapper = UpnpPortMapper::with_lease_duration(addr, 100);
        assert_eq!(mapper.default_lease_duration, MIN_LEASE_DURATION);

        // Test clamping to maximum
        let mapper = UpnpPortMapper::with_lease_duration(addr, 100000);
        assert_eq!(mapper.default_lease_duration, MAX_LEASE_DURATION);

        // Test valid value
        let mapper = UpnpPortMapper::with_lease_duration(addr, 1800);
        assert_eq!(mapper.default_lease_duration, 1800);
    }

    #[tokio::test]
    async fn test_upnp_mapper_loopback_rejection() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut mapper = UpnpPortMapper::new(addr);

        // Discovery should fail for loopback
        let result = mapper.discover().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn test_upnp_mapper_disabled() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mut mapper = UpnpPortMapper::new(addr);
        mapper.disable();

        let result = mapper.discover().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn test_upnp_mapper_no_gateway() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mapper = UpnpPortMapper::new(addr);

        // Should fail because discover() wasn't called
        let result = mapper.add_mapping(12345).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No UPnP gateway"));
    }

    #[test]
    fn test_try_create_upnp_candidate_loopback() {
        // Should return None for loopback addresses
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
            try_create_upnp_candidate(addr).await
        });
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_upnp_mapper_clone() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mapper = UpnpPortMapper::new(addr);

        let cloned = mapper.clone();
        assert_eq!(cloned.local_addr, addr);
        assert!(cloned.is_enabled());
        // Gateway should be None in clone (not cloneable)
        assert!(!cloned.has_gateway());
    }

    #[test]
    fn test_mapping_constants() {
        assert!(MIN_LEASE_DURATION > 0);
        assert!(MAX_LEASE_DURATION > MIN_LEASE_DURATION);
        assert!(DEFAULT_LEASE_DURATION >= MIN_LEASE_DURATION);
        assert!(DEFAULT_LEASE_DURATION <= MAX_LEASE_DURATION);
    }
}
