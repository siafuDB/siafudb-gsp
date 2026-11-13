//! Minimal `key=value` logging to stderr.
//!
//! Callers pass only fragment-id prefixes, counts, sizes and status codes.
//! Tokens, token hashes, item bytes and client addresses are never logged.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn stderr logging on or off for the whole process (default: off, so
/// embedding the library and running tests stays quiet).
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Short, non-reversible-enough label for a fragment id in logs: the first
/// four bytes in hex. Fragment ids are public routing ids, not secrets.
pub fn frag(id: &[u8]) -> String {
    let mut s = String::with_capacity(8);
    for b in id.iter().take(4) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) fn emit(level: &str, event: &str, fields: std::fmt::Arguments<'_>) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    eprintln!("ts={ts} level={level} event={event} {fields}");
}

macro_rules! info {
    ($event:expr, $($arg:tt)*) => { $crate::log::emit("info", $event, format_args!($($arg)*)) };
}
macro_rules! warn {
    ($event:expr, $($arg:tt)*) => { $crate::log::emit("warn", $event, format_args!($($arg)*)) };
}
pub(crate) use {info, warn};
