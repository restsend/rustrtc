//! UPnP IGD (Internet Gateway Device) support for ICE
//!
//! This module provides port mapping functionality using UPnP IGD protocol.
//! It allows direct peer-to-peer connections through NAT by mapping external
//! ports to internal addresses.

use crate::transports::ice::IceCandidate;
use anyhow::{Result, anyhow};
use igd::AddPortError;
use igd::PortMappingProtocol;
use igd::aio::Gateway;
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

/// Default timeout for a single SOAP request to the IGD (AddPortMapping,
/// GetExternalIPAddress, ...). The `igd` crate's aio client has no built-in
/// timeout and can hang forever on a slow/unresponsive router, which would
/// block ICE gathering completion indefinitely.
pub const DEFAULT_UPNP_SOAP_TIMEOUT: Duration = Duration::from_secs(1);

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

    /// Inject a gateway directly (test-only). The `Gateway` fields are all
    /// `pub`, so tests can point one at a local mock SOAP IGD server.
    #[cfg(test)]
    pub fn set_gateway_for_test(&mut self, gateway: Gateway) {
        self.gateway = Some(gateway);
    }

    /// Insert a mapping directly with the given age (test-only), bypassing the
    /// router. Used to drive `is_expired_or_stale` in renewal tests.
    #[cfg(test)]
    pub async fn insert_mapping_for_test(&self, external_port: u16, age: Duration) {
        let mut mappings = self.mappings.lock().await;
        mappings.insert(
            external_port,
            PortMapping {
                external_port,
                internal_addr: self.local_addr,
                lease_duration: self.default_lease_duration,
                description: format!("rustrtc-{}", self.local_addr.port()),
                created_at: std::time::Instant::now().checked_sub(age).unwrap(),
            },
        );
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
        self.discover_with_timeout(DEFAULT_UPNP_DISCOVERY_TIMEOUT)
            .await
    }

    /// Discover and connect to a UPnP IGD gateway with custom timeout
    ///
    /// This method searches for UPnP IGD devices on the local network
    /// and attempts to connect to the first one found.
    pub async fn discover_with_timeout(&mut self, timeout_duration: Duration) -> Result<()> {
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

        let gateway = timeout(
            timeout_duration,
            igd::aio::search_gateway(Default::default()),
        )
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

        let ip = timeout(DEFAULT_UPNP_SOAP_TIMEOUT, gateway.get_external_ip())
            .await
            .map_err(|_| {
                anyhow!(
                    "UPnP GetExternalIP timed out after {:?}",
                    DEFAULT_UPNP_SOAP_TIMEOUT
                )
            })?
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

        match timeout(DEFAULT_UPNP_SOAP_TIMEOUT, gateway.add_port(
            PortMappingProtocol::UDP,
            requested_port,
            internal_sock_addr,
            self.default_lease_duration,
            &description,
        ))
        .await
        {
            Ok(Ok(())) => {
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
            Ok(Err(e)) => {
                // If the requested port is taken, try with port 0 (random)
                if external_port != 0 && requested_port != 0 {
                    warn!(
                        "Port {} is taken, trying random port: {}",
                        requested_port, e
                    );
                    // Avoid recursion by manually trying a random port
                    self.add_mapping_random_port(gateway, external_ip, local_ip)
                        .await
                } else {
                    Err(anyhow!("Failed to add UPnP port mapping: {}", e))
                }
            }
            Err(_) => {
                warn!(
                    "UPnP AddPortMapping timed out after {:?}, trying random port: {}",
                    DEFAULT_UPNP_SOAP_TIMEOUT,
                    requested_port
                );
                // Avoid recursion by manually trying a random port
                self.add_mapping_random_port(gateway, external_ip, local_ip)
                    .await
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

            match timeout(
                DEFAULT_UPNP_SOAP_TIMEOUT,
                gateway.add_port(
                    PortMappingProtocol::UDP,
                    port,
                    internal_sock_addr,
                    self.default_lease_duration,
                    &description,
                ),
            )
            .await
            {
                Ok(Ok(())) => {
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
                Ok(Err(_)) => continue,
                Err(_) => {
                    warn!(
                        "UPnP AddPortMapping timed out after {:?} for port {}, skipping",
                        DEFAULT_UPNP_SOAP_TIMEOUT, port
                    );
                    continue;
                }
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

        timeout(
            DEFAULT_UPNP_SOAP_TIMEOUT,
            gateway.remove_port(PortMappingProtocol::UDP, external_port),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "UPnP RemovePortMapping timed out after {:?}",
                DEFAULT_UPNP_SOAP_TIMEOUT
            )
        })?
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

    /// Refresh a mapping's lease by re-issuing AddPortMapping with the same
    /// external port, WITHOUT deleting the mapping first.
    ///
    /// Re-issuing AddPortMapping for an existing external port renews the lease
    /// on most IGDs with no inbound-path gap. This is the safe way to keep a
    /// long-lived mapping alive past the router's lease duration.
    ///
    /// Returns:
    ///   - `Ok(true)` if the mapping was refreshed or re-added
    ///   - `Ok(false)` if the mapping doesn't exist locally (nothing to refresh)
    pub async fn refresh_mapping(&self, external_port: u16) -> Result<bool> {
        let gateway = match &self.gateway {
            Some(g) => g,
            None => return Ok(false), // No gateway, nothing to refresh
        };

        let mapping = {
            let mappings = self.mappings.lock().await;
            match mappings.get(&external_port) {
                Some(m) => m.clone(),
                None => return Ok(false),
            }
        };

        let local_ip = match mapping.internal_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 not supported for UPnP IGD")),
        };
        let internal_sock_addr = SocketAddrV4::new(local_ip, mapping.internal_addr.port());

        // Try a plain re-issue first (idempotent lease refresh on most routers).
        // Only fall back to delete-then-add if the router reports PortInUse.
        let refreshed = match timeout(
            DEFAULT_UPNP_SOAP_TIMEOUT,
            gateway.add_port(
                PortMappingProtocol::UDP,
                external_port,
                internal_sock_addr,
                self.default_lease_duration,
                &mapping.description,
            ),
        )
        .await
        {
            Ok(Ok(())) => true,
            Err(_) => {
                warn!(
                    "UPnP refresh AddPortMapping timed out after {:?} for port {}",
                    DEFAULT_UPNP_SOAP_TIMEOUT, external_port
                );
                false
            }
            Ok(Err(AddPortError::PortInUse)) => {
                // Router thinks the port belongs to someone else (e.g. a stale
                // entry). Remove then re-add — but NEVER switch to a random port:
                // changing the external port would break the negotiated ICE
                // candidate.
                let _ = self.remove_mapping(external_port).await;
                timeout(
                    DEFAULT_UPNP_SOAP_TIMEOUT,
                    gateway.add_port(
                        PortMappingProtocol::UDP,
                        external_port,
                        internal_sock_addr,
                        self.default_lease_duration,
                        &mapping.description,
                    ),
                )
                .await
                .map_err(|_| {
                    anyhow!(
                        "UPnP re-add timed out after {:?}",
                        DEFAULT_UPNP_SOAP_TIMEOUT
                    )
                })?
                .map_err(|e| {
                    anyhow!("Failed to re-add UPnP mapping after conflict: {}", e)
                })?;
                true
            }
            Ok(Err(AddPortError::OnlyPermanentLeasesSupported)) => {
                // Router only supports permanent (lease 0) mappings; refresh is
                // effectively a no-op since the mapping never expires. Reset the
                // local staleness clock so we stop hammering the router.
                true
            }
            Ok(Err(e)) => {
                return Err(anyhow!("Failed to refresh UPnP mapping: {}", e));
            }
        };

        if refreshed {
            {
                let mut mappings = self.mappings.lock().await;
                if let Some(m) = mappings.get_mut(&external_port) {
                    m.created_at = std::time::Instant::now();
                }
            }
            debug!("Refreshed UPnP mapping for port {}", external_port);
        }

        Ok(refreshed)
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

        self.refresh_mapping(external_port).await
    }

    /// Renew all stale mappings
    ///
    /// Best-effort: a failure on one mapping is logged and renewal continues
    /// with the rest, so a single transient router error never blocks the
    /// refresh cycle. Returns the number of mappings that were renewed.
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
            match self.renew_mapping(port).await {
                Ok(true) => renewed += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!("Failed to renew UPnP mapping for port {}: {}", port, e);
                }
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

/// Shared in-process mock UPnP IGD used by upnp unit tests and the ICE
/// runner integration tests (`ice::tests`). Serves SOAP responses over a
/// loopback TCP listener so the real `igd` client code path is exercised.
#[cfg(test)]
pub(crate) mod test_mock_igd {
    use super::*;
    use igd::aio::Gateway;
    use std::collections::VecDeque;
    use std::net::SocketAddrV4;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;

    #[derive(Debug, Clone)]
    pub enum MockAddResponse {
        Ok,
        PortInUse,
        PermanentOnly,
        Unauthorized,
    }

    /// Minimal in-process UPnP IGD. Ignores the SOAP body; decides the reply
    /// from the `SOAPAction` header, with a programmable queue of responses for
    /// AddPortMapping. Tracks how many AddPortMapping / DeletePortMapping
    /// requests it received so tests can assert the exact sequence.
    #[derive(Debug, Clone)]
    pub struct MockIgd {
        addr: SocketAddrV4,
        pub add_calls: Arc<AtomicUsize>,
        pub delete_calls: Arc<AtomicUsize>,
        add_queue: Arc<TokioMutex<VecDeque<MockAddResponse>>>,
    }

    impl MockIgd {
        pub async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let addr_v4 = match addr {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!("bound to IPv4 loopback"),
            };
            let this = Self {
                addr: addr_v4,
                add_calls: Arc::new(AtomicUsize::new(0)),
                delete_calls: Arc::new(AtomicUsize::new(0)),
                add_queue: Arc::new(TokioMutex::new(VecDeque::new())),
            };
            let server = this.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        break;
                    };
                    let server = server.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 8192];
                        let n = match sock.read(&mut buf).await {
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let soap_action = req
                            .lines()
                            .find_map(|l| {
                                let lower = l.to_ascii_lowercase();
                                lower
                                    .starts_with("soapaction:")
                                    .then(|| l["soapaction:".len()..].trim().to_string())
                            })
                            .unwrap_or_default();
                        // "urn:...:WANIPConnection:1#Action"
                        let action = soap_action
                            .rsplit('#')
                            .next()
                            .unwrap_or("")
                            .trim_matches('"')
                            .to_string();

                        let body = server.handle_action(&action).await;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(response.as_bytes()).await;
                    });
                }
            });
            this
        }

        pub async fn handle_action(&self, action: &str) -> String {
            if action.contains("GetExternalIPAddress") {
                return ok_response(
                    "GetExternalIPAddressResponse",
                    "<NewExternalIPAddress>203.0.113.1</NewExternalIPAddress>",
                );
            }
            if action.contains("AddPortMapping") {
                let _ = self.add_calls.fetch_add(1, Ordering::SeqCst);
                let resp = {
                    let mut q = self.add_queue.lock().await;
                    q.pop_front().unwrap_or(MockAddResponse::Ok)
                };
                return match resp {
                    MockAddResponse::Ok => ok_response("AddPortMappingResponse", ""),
                    MockAddResponse::PortInUse => error_response(718, "ConflictInMappingEntry"),
                    MockAddResponse::PermanentOnly => {
                        error_response(725, "OnlyPermanentLeasesSupported")
                    }
                    MockAddResponse::Unauthorized => error_response(606, "ActionNotAuthorized"),
                };
            }
            if action.contains("DeletePortMapping") {
                let _ = self.delete_calls.fetch_add(1, Ordering::SeqCst);
                return ok_response("DeletePortMappingResponse", "");
            }
            error_response(401, "InvalidAction")
        }

        pub fn gateway(&self) -> Gateway {
            let mut schema = HashMap::new();
            schema.insert(
                "AddPortMapping".to_string(),
                vec![
                    "NewEnabled".to_string(),
                    "NewExternalPort".to_string(),
                    "NewInternalClient".to_string(),
                    "NewInternalPort".to_string(),
                    "NewLeaseDuration".to_string(),
                    "NewPortMappingDescription".to_string(),
                    "NewProtocol".to_string(),
                    "NewRemoteHost".to_string(),
                ],
            );
            schema.insert(
                "DeletePortMapping".to_string(),
                vec![
                    "NewExternalPort".to_string(),
                    "NewProtocol".to_string(),
                    "NewRemoteHost".to_string(),
                ],
            );
            Gateway {
                addr: self.addr,
                root_url: format!("http://{}/", self.addr),
                control_url: "/upnp/control".to_string(),
                control_schema_url: "/upnp/control/scpd.xml".to_string(),
                control_schema: schema,
            }
        }

        pub async fn enqueue_add(&self, resp: MockAddResponse) {
            self.add_queue.lock().await.push_back(resp);
        }
    }

    pub fn ok_response(name: &str, inner: &str) -> String {
        soap_envelope(&format!(
            r#"<u:{name} xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{inner}</u:{name}>"#
        ))
    }

    pub fn error_response(code: u16, desc: &str) -> String {
        soap_envelope(&format!(
            r#"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError><errorCode>{code}</errorCode><errorDescription>{desc}</errorDescription></UPnPError>
</detail></s:Fault>"#
        ))
    }

    pub fn soap_envelope(body: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>{body}</s:Body>
</s:Envelope>"#
        )
    }

    pub const STALE_AGE: Duration = Duration::from_secs(3540); // lease 3600, stale at >= 3540
    pub const FRESH_AGE: Duration = Duration::from_secs(60);
}

#[cfg(test)]
mod tests {
    use super::test_mock_igd::{FRESH_AGE, MockAddResponse, MockIgd, STALE_AGE};
    use super::*;
    use std::sync::atomic::Ordering;

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
        assert!((69..=70).contains(&remaining));
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
        assert!(
            new_remaining <= remaining,
            "remaining={}, new_remaining={}",
            remaining,
            new_remaining
        );
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
        assert!(result.unwrap_err().to_string().contains("No UPnP gateway"));
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
    #[allow(clippy::assertions_on_constants)] // intentional compile-time invariant checks
    fn test_mapping_constants() {
        assert!(MIN_LEASE_DURATION > 0);
        assert!(MAX_LEASE_DURATION > MIN_LEASE_DURATION);
        assert!(DEFAULT_LEASE_DURATION >= MIN_LEASE_DURATION);
        assert!(DEFAULT_LEASE_DURATION <= MAX_LEASE_DURATION);
    }

    #[tokio::test]
    async fn test_refresh_mapping_reissues_add_without_delete() {
        let mock = MockIgd::start().await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10001, STALE_AGE).await;

        let renewed = mapper.renew_mapping(10001).await.unwrap();
        assert!(renewed, "stale mapping must be renewed");
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.delete_calls.load(Ordering::SeqCst), 0);
        // Local staleness clock reset: mapping no longer stale.
        assert!(
            !mapper.mappings.lock().await[&10001].is_expired_or_stale(),
            "created_at must be reset after refresh"
        );
    }

    #[tokio::test]
    async fn test_refresh_mapping_router_lost_mapping_readds() {
        // If the router dropped the mapping (lease expired on the router), a
        // plain AddPortMapping simply re-creates it — same happy path as
        // refresh. Verify the mapping is restored and the clock reset.
        let mock = MockIgd::start().await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10002, STALE_AGE).await;

        let renewed = mapper.renew_mapping(10002).await.unwrap();
        assert!(renewed);
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.delete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_refresh_mapping_port_in_use_falls_back_to_delete_then_add() {
        let mock = MockIgd::start().await;
        mock.enqueue_add(MockAddResponse::PortInUse).await; // first add -> 718
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10003, STALE_AGE).await;

        let renewed = mapper.renew_mapping(10003).await.unwrap();
        assert!(renewed, "PortInUse fallback should still renew");
        assert_eq!(
            mock.add_calls.load(Ordering::SeqCst),
            2,
            "expect delete-then-add: two AddPortMapping calls"
        );
        assert_eq!(
            mock.delete_calls.load(Ordering::SeqCst),
            1,
            "expect one DeletePortMapping before re-add"
        );
    }

    #[tokio::test]
    async fn test_refresh_mapping_never_switches_port_on_conflict() {
        // The critical invariant: on PortInUse we must NOT fall back to a
        // random port (that would break the negotiated ICE candidate). The
        // mock can't observe the port directly from SOAP body (ignored), but
        // verifying the exact add/delete call sequence (2 adds, 1 delete, no
        // random-port scan) is the observable contract.
        let mock = MockIgd::start().await;
        mock.enqueue_add(MockAddResponse::PortInUse).await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10004, STALE_AGE).await;

        let renewed = mapper.renew_mapping(10004).await.unwrap();
        assert!(renewed);
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 2);
        assert_eq!(mock.delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_refresh_mapping_only_permanent_lease_supported() {
        // Router only supports permanent leases: refresh is a no-op but we must
        // not error out or loop — reset the clock so we stop re-hitting it.
        let mock = MockIgd::start().await;
        mock.enqueue_add(MockAddResponse::PermanentOnly).await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10005, STALE_AGE).await;

        let renewed = mapper.renew_mapping(10005).await.unwrap();
        assert!(renewed);
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.delete_calls.load(Ordering::SeqCst), 0);
        assert!(!mapper.mappings.lock().await[&10005].is_expired_or_stale());
    }

    #[tokio::test]
    async fn test_refresh_mapping_unauthorized_returns_error() {
        let mock = MockIgd::start().await;
        mock.enqueue_add(MockAddResponse::Unauthorized).await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10006, STALE_AGE).await;

        let result = mapper.renew_mapping(10006).await;
        assert!(result.is_err(), "non-recoverable router error must surface");
    }

    #[tokio::test]
    async fn test_renew_mapping_missing_locally_returns_false() {
        let mock = MockIgd::start().await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        // No mapping inserted.
        let renewed = mapper.renew_mapping(10007).await.unwrap();
        assert!(!renewed);
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 0);
        assert_eq!(mock.delete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_renew_mapping_no_gateway_returns_false() {
        let mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.insert_mapping_for_test(10008, STALE_AGE).await;
        let renewed = mapper.renew_mapping(10008).await.unwrap();
        assert!(!renewed, "no gateway -> nothing to refresh, must not error");
    }

    #[tokio::test]
    async fn test_renew_all_stale_skips_fresh_mappings() {
        let mock = MockIgd::start().await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10009, FRESH_AGE).await;

        let renewed = mapper.renew_all_stale().await.unwrap();
        assert_eq!(renewed, 0);
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_renew_all_stale_continues_on_error() {
        // First mapping fails (unauthorized), second succeeds — best-effort
        // renewal must not abort on the first failure.
        let mock = MockIgd::start().await;
        mock.enqueue_add(MockAddResponse::Unauthorized).await;
        let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.set_gateway_for_test(mock.gateway());
        mapper.insert_mapping_for_test(10010, STALE_AGE).await;
        mapper.insert_mapping_for_test(10011, STALE_AGE).await;

        let renewed = mapper.renew_all_stale().await.unwrap();
        assert_eq!(renewed, 1, "second mapping must still be renewed");
        assert_eq!(mock.add_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_renew_all_stale_no_gateway_is_noop() {
        let mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
        mapper.insert_mapping_for_test(10012, STALE_AGE).await;
        let renewed = mapper.renew_all_stale().await.unwrap();
        assert_eq!(renewed, 0, "no gateway -> no mappings renewed, no error");
    }
}
