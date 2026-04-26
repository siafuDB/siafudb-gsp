// siafudb-sync/src/discovery/announcement.rs
//
// A peer announcement is what a SiafuDB instance broadcasts on the
// local network via mDNS. It carries just enough information for
// other instances to decide whether to sync, without revealing
// any actual graph data.

use serde::{Deserialize, Serialize};
use siafudb_core::fragment::FragmentKind;
use uuid::Uuid;

/// The mDNS service type for SiafuDB instances.
/// Format follows RFC 6763: _service._protocol.local
pub const MDNS_SERVICE_TYPE: &str = "_siafudb._tcp.local.";

/// Information broadcast by a SiafuDB instance on the local network.
///
/// This is transmitted as mDNS TXT records alongside the service
/// announcement. It's intentionally minimal — just enough to make
/// a sync decision, no actual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// The unique instance ID of the announcing SiafuDB.
    pub instance_id: Uuid,

    /// The public identity of the instance's owner.
    /// This is the ed25519 public key, encoded as hex or base64.
    /// Other instances compare this to their own owner identity to
    /// determine if this is the same person's device.
    pub owner_public_key: String,

    /// What kind of fragment this instance holds.
    /// Other instances use this to determine what kind of sync
    /// is appropriate (personal-to-personal, personal-to-pod, etc).
    pub fragment_kind: FragmentKind,

    /// The port where this instance's sync endpoint is listening.
    /// The IP address comes from the mDNS announcement itself.
    pub sync_port: u16,

    /// The sync protocol version this instance supports.
    /// Used for compatibility checking before attempting sync.
    pub protocol_version: String,

    /// Which adapters this instance supports.
    /// Typically ["gspa"] for now, eventually ["gspa", "gspn"].
    pub supported_adapters: Vec<String>,

    /// A human-readable device name (e.g., "Amara's iPhone", "Work Laptop").
    /// Optional. Used for display in device management UI.
    pub device_name: Option<String>,
}

impl PeerAnnouncement {
    /// Check whether this announcement represents a device owned by
    /// the same person as the given public key.
    ///
    /// If the owner public keys match, these are the same person's
    /// devices and should auto-sync personal data.
    pub fn is_same_owner(&self, our_public_key: &str) -> bool {
        self.owner_public_key == our_public_key
    }

    /// Check whether this peer supports a specific adapter.
    pub fn supports_adapter(&self, adapter: &str) -> bool {
        self.supported_adapters.iter().any(|a| a == adapter)
    }

    /// Convert to mDNS TXT record key-value pairs.
    /// Each field becomes a TXT record entry like "id=abc-123".
    pub fn to_txt_records(&self) -> Vec<(String, String)> {
        let mut records = vec![
            ("id".to_string(), self.instance_id.to_string()),
            ("owner".to_string(), self.owner_public_key.clone()),
            ("kind".to_string(), format!("{:?}", self.fragment_kind)),
            ("port".to_string(), self.sync_port.to_string()),
            ("proto".to_string(), self.protocol_version.clone()),
            (
                "adapters".to_string(),
                self.supported_adapters.join(","),
            ),
        ];

        if let Some(name) = &self.device_name {
            records.push(("name".to_string(), name.clone()));
        }

        records
    }
}
