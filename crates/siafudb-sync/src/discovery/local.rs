// siafudb-sync/src/discovery/local.rs
//
// THE LOCAL DISCOVERY ENGINE
//
// Manages the mDNS service registration and listener for this
//
// NOTE: the allow(dead_code, unused_imports) below covers imports and
// fields used by the mDNS implementation that lands once the discovery
// engine is fleshed out. Remove the allow once the TODO bodies are real.

#![allow(dead_code, unused_imports)]

// Manages the mDNS service registration and listener for this
// SiafuDB instance. Automatically discovers peers on the local
// network and initiates sync when appropriate.
//
// The discovery engine runs as a background task alongside the
// sync engine. It doesn't handle the actual sync — it just tells
// the sync engine "I found a peer, here's their info, you decide
// what to do."

use super::announcement::{MDNS_SERVICE_TYPE, PeerAnnouncement};
use siafudb_core::error::SiafuError;
use siafudb_core::fragment::FragmentKind;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// A discovered peer on the local network.
///
/// Contains the peer's announcement plus the network address
/// resolved from mDNS, which is everything the sync engine
/// needs to initiate a connection.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// The peer's announcement (identity, fragment kind, etc).
    pub announcement: PeerAnnouncement,

    /// The peer's IP address on the local network.
    pub address: IpAddr,

    /// When this peer was last seen (Unix timestamp).
    pub last_seen: u64,

    /// Whether we've successfully synced with this peer before.
    pub previously_synced: bool,
}

/// The local network discovery engine.
///
/// Call `start()` to begin broadcasting this instance's presence
/// and listening for other instances on the network. The engine
/// maintains a registry of discovered peers that the sync engine
/// can query when deciding what to sync with.
pub struct LocalDiscovery {
    /// This instance's announcement (what we broadcast).
    our_announcement: PeerAnnouncement,

    /// Discovered peers, keyed by instance ID.
    peers: HashMap<Uuid, DiscoveredPeer>,

    /// Public keys of authorised peers (for cross-user sync).
    /// These are peers that aren't the same owner but are
    /// authorised to sync specific data (e.g., friends who
    /// have opted into direct sync).
    authorised_peers: Vec<String>,

    /// Whether the discovery engine is running.
    running: bool,
}

impl LocalDiscovery {
    /// Create a new discovery engine for the given instance.
    pub fn new(announcement: PeerAnnouncement) -> Self {
        Self {
            our_announcement: announcement,
            peers: HashMap::new(),
            authorised_peers: Vec::new(),
            running: false,
        }
    }

    /// Start the discovery engine.
    ///
    /// This does two things:
    /// 1. Registers this instance as an mDNS service so other
    ///    SiafuDB instances on the network can find us.
    /// 2. Starts listening for other SiafuDB instances' mDNS
    ///    announcements on the network.
    ///
    /// In a full implementation, this would spawn a background
    /// tokio task that runs the mDNS listener continuously.
    pub async fn start(&mut self) -> Result<(), SiafuError> {
        // TODO: Register mDNS service using mdns-sd crate.
        //
        // let mdns = ServiceDaemon::new()?;
        // let service = ServiceInfo::new(
        //     MDNS_SERVICE_TYPE,
        //     &self.our_announcement.instance_id.to_string(),
        //     &hostname,
        //     &local_ip,
        //     self.our_announcement.sync_port,
        //     self.our_announcement.to_txt_records(),
        // )?;
        // mdns.register(service)?;
        //
        // Spawn listener task:
        // let receiver = mdns.browse(MDNS_SERVICE_TYPE)?;
        // tokio::spawn(async move {
        //     while let Ok(event) = receiver.recv_async().await {
        //         match event {
        //             ServiceEvent::ServiceResolved(info) => {
        //                 // Parse announcement from TXT records
        //                 // Add to peers registry
        //                 // Notify sync engine
        //             }
        //             ServiceEvent::ServiceRemoved(_, name) => {
        //                 // Remove from peers registry
        //             }
        //             _ => {}
        //         }
        //     }
        // });

        tracing::info!(
            "Local discovery started for instance {}",
            self.our_announcement.instance_id
        );
        self.running = true;
        Ok(())
    }

    /// Stop the discovery engine.
    ///
    /// Sends an mDNS goodbye announcement so peers know we're
    /// leaving, and stops the listener.
    pub async fn stop(&mut self) -> Result<(), SiafuError> {
        // TODO: Unregister mDNS service (sends goodbye).
        // Stop the listener task.
        tracing::info!(
            "Local discovery stopped for instance {}",
            self.our_announcement.instance_id
        );
        self.running = false;
        Ok(())
    }

    /// Handle a discovered peer announcement.
    ///
    /// Called by the mDNS listener when a new SiafuDB instance
    /// is found on the network. Evaluates whether sync is
    /// appropriate and adds to the peer registry if so.
    pub fn on_peer_discovered(
        &mut self,
        announcement: PeerAnnouncement,
        address: IpAddr,
    ) -> Option<SyncDecision> {
        // Don't sync with ourselves.
        if announcement.instance_id == self.our_announcement.instance_id {
            return None;
        }

        // Don't re-add peers we already know about (just update last_seen).
        if let Some(existing) = self.peers.get_mut(&announcement.instance_id) {
            existing.last_seen = current_timestamp();
            return None;
        }

        // Determine the sync decision based on the relationship
        // between this instance and the discovered peer.
        let decision = self.evaluate_peer(&announcement);

        // Add to registry regardless of decision (we want to know
        // they're there even if we don't sync with them now).
        self.peers.insert(
            announcement.instance_id,
            DiscoveredPeer {
                announcement: announcement.clone(),
                address,
                last_seen: current_timestamp(),
                previously_synced: false,
            },
        );

        decision
    }

    /// Evaluate whether to sync with a discovered peer.
    fn evaluate_peer(&self, peer: &PeerAnnouncement) -> Option<SyncDecision> {
        let our_key = &self.our_announcement.owner_public_key;

        // Case 1: Same owner — this is another one of our devices.
        // Auto-sync personal data without user intervention.
        if peer.is_same_owner(our_key) {
            return Some(SyncDecision::AutoSync {
                reason: SyncReason::SameOwner,
                adapter: self.choose_adapter(peer),
            });
        }

        // Case 2: Authorised peer — someone we've explicitly paired with.
        // Sync shared data (conversations, shared circles, etc).
        if self.authorised_peers.contains(&peer.owner_public_key) {
            return Some(SyncDecision::AutoSync {
                reason: SyncReason::AuthorisedPeer,
                adapter: self.choose_adapter(peer),
            });
        }

        // Case 3: Unknown peer — we don't know this device.
        // Don't sync. They're just another SiafuDB on the network.
        None
    }

    /// Choose the best adapter for syncing with a peer.
    ///
    /// Prefers GSPN if both sides support it, falls back to GSPA.
    /// For local network sync, GSPA uses the Local transport variant
    /// which is optimised for LAN conditions (binary format, no JSON
    /// serialisation, minimal overhead).
    fn choose_adapter(&self, peer: &PeerAnnouncement) -> AdapterChoice {
        let we_support_gspn = self
            .our_announcement
            .supported_adapters
            .iter()
            .any(|a| a == "gspn");
        let they_support_gspn = peer.supports_adapter("gspn");

        if we_support_gspn && they_support_gspn {
            AdapterChoice::Gspn
        } else {
            AdapterChoice::GspaLocal
        }
    }

    /// Add an authorised peer public key.
    ///
    /// Called when the user pairs with another person's device
    /// (e.g., scanning a QR code, entering a pairing code).
    /// After pairing, the other person's devices will be auto-synced
    /// when discovered on the local network.
    pub fn authorise_peer(&mut self, public_key: String) {
        if !self.authorised_peers.contains(&public_key) {
            self.authorised_peers.push(public_key);
        }
    }

    /// Get all currently discovered peers.
    pub fn discovered_peers(&self) -> Vec<&DiscoveredPeer> {
        self.peers.values().collect()
    }

    /// Get only the peers we should be syncing with.
    pub fn syncable_peers(&self) -> Vec<&DiscoveredPeer> {
        self.peers
            .values()
            .filter(|peer| {
                let our_key = &self.our_announcement.owner_public_key;
                peer.announcement.is_same_owner(our_key)
                    || self
                        .authorised_peers
                        .contains(&peer.announcement.owner_public_key)
            })
            .collect()
    }

    /// Remove peers that haven't been seen recently.
    /// Called periodically to clean up the registry.
    pub fn prune_stale_peers(&mut self, max_age_seconds: u64) {
        let cutoff = current_timestamp().saturating_sub(max_age_seconds);
        self.peers.retain(|_, peer| peer.last_seen >= cutoff);
    }
}

/// The decision made when a peer is discovered.
#[derive(Debug, Clone)]
pub enum SyncDecision {
    /// Automatically initiate sync with this peer.
    AutoSync {
        /// Why we're syncing.
        reason: SyncReason,
        /// Which adapter to use.
        adapter: AdapterChoice,
    },
}

/// Why a sync was initiated.
#[derive(Debug, Clone)]
pub enum SyncReason {
    /// The peer belongs to the same user (same owner key).
    SameOwner,
    /// The peer is an explicitly authorised partner.
    AuthorisedPeer,
}

/// Which adapter to use for sync.
#[derive(Debug, Clone)]
pub enum AdapterChoice {
    /// GSPA with local transport (TCP + mutual TLS, binary format).
    /// Used when one or both peers don't support GSPN.
    GspaLocal,
    /// GSPN (NTL signal propagation).
    /// Used when both peers have NTL running locally.
    Gspn,
}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
