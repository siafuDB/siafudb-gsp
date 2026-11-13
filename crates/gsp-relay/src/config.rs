//! Relay configuration: limits, CORS origin, and the binary's flag/env parser.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Upper bound for `wait_ms` fixed by SYNC-V0 section 6.
pub const MAX_WAIT_MS: u64 = 25_000;

/// Bytes charged against quotas for every stored item on top of its own
/// length. It covers the on-disk record header and the in-memory index entry,
/// so a client cannot exhaust memory with millions of tiny items while staying
/// under the byte quota.
pub const ITEM_OVERHEAD: u64 = 64;

/// When the directory store calls `fsync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fsync {
    /// `fdatasync` the fragment log once per push, before the `Ack` is sent.
    /// An acknowledged item survives a crash or power loss.
    Always,
    /// Never sync item writes; the OS flushes when it likes. After a crash,
    /// acknowledged items may be gone and their cursors reused.
    Never,
}

/// An operator secret. `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }
    /// The value. Do not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Limits and policy for one relay instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Value of `access-control-allow-origin` (default `*`).
    pub cors_origin: String,
    /// Largest encoded `SealedOp` accepted, in bytes (default 256 KiB).
    pub max_item_bytes: usize,
    /// Largest request body, in bytes (default 1 MiB).
    pub max_request_bytes: usize,
    /// Most items in one `Push` (default 64).
    pub max_push_items: usize,
    /// Most items in one `Batch` (default 256).
    pub max_batch_items: usize,
    /// Soft cap on the item bytes in one `Batch` (default 1 MiB). A `Batch`
    /// always carries at least one item when one is available.
    pub max_batch_bytes: usize,
    /// Per-fragment quota in bytes, counting [`ITEM_OVERHEAD`] per item
    /// (default 64 MiB).
    pub fragment_quota_bytes: u64,
    /// Quota across all fragments, same accounting (default 4 GiB).
    pub total_quota_bytes: u64,
    /// Most fragments the relay will register (default 4096).
    pub max_fragments: usize,
    /// If set, the first push to a new fragment must carry this value in the
    /// `x-gsp-registration` header. Fragments that already exist are not
    /// affected. Default: unset, anyone who can reach the relay may register.
    pub registration_token: Option<Secret>,
    /// Most request-body bytes being decoded at the same time (default
    /// 8 MiB). A push that does not fit right now gets `503`.
    pub max_decode_bytes: usize,
    /// Most concurrent long-polls on one fragment (default 8).
    pub max_polls_per_fragment: usize,
    /// Most concurrent long-polls overall (default 512).
    pub max_polls: usize,
    /// Most open TCP connections; further ones are closed on accept
    /// (default 1024).
    pub max_connections: usize,
    /// Time allowed to receive request headers, and separately a request
    /// body (default 15 s).
    pub read_timeout: Duration,
    /// How long shutdown waits for in-flight requests (default 10 s).
    pub shutdown_grace: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cors_origin: "*".into(),
            max_item_bytes: 256 * 1024,
            max_request_bytes: 1024 * 1024,
            max_push_items: 64,
            max_batch_items: 256,
            max_batch_bytes: 1024 * 1024,
            fragment_quota_bytes: 64 * 1024 * 1024,
            total_quota_bytes: 4 * 1024 * 1024 * 1024,
            max_fragments: 4096,
            registration_token: None,
            max_decode_bytes: 8 * 1024 * 1024,
            max_polls_per_fragment: 8,
            max_polls: 512,
            max_connections: 1024,
            read_timeout: Duration::from_secs(15),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl Config {
    /// Reject configurations the relay cannot run with.
    pub fn validate(&self) -> Result<(), String> {
        if hyper::header::HeaderValue::from_str(&self.cors_origin).is_err()
            || self.cors_origin.is_empty()
        {
            return Err("cors origin is not a valid header value".into());
        }
        let nonzero = [
            ("max item bytes", self.max_item_bytes),
            ("max request bytes", self.max_request_bytes),
            ("max push items", self.max_push_items),
            ("max batch items", self.max_batch_items),
            ("max batch bytes", self.max_batch_bytes),
            ("max connections", self.max_connections),
        ];
        for (name, v) in nonzero {
            if v == 0 {
                return Err(format!("{name} must be greater than 0"));
            }
        }
        if self.max_decode_bytes < self.max_request_bytes
            || self.max_decode_bytes > (u32::MAX >> 4) as usize
        {
            return Err(
                "max decode bytes must be at least max request bytes and below 256 MiB".into(),
            );
        }
        if let Some(t) = &self.registration_token
            && (t.expose().is_empty()
                || hyper::header::HeaderValue::from_str(t.expose()).is_err()
                || t.expose().trim() != t.expose())
        {
            return Err(
                "registration token must be non-empty visible ASCII without surrounding spaces"
                    .into(),
            );
        }
        if self.max_item_bytes > crate::dirstore::MAX_RECORD_BYTES {
            return Err(format!(
                "max item bytes must be at most {}",
                crate::dirstore::MAX_RECORD_BYTES
            ));
        }
        Ok(())
    }
}

/// Everything the binary needs to start.
#[derive(Debug, Clone)]
pub struct Options {
    /// Listen address (default `127.0.0.1:8787`).
    pub addr: SocketAddr,
    /// Directory for the durable store. `None` only together with
    /// `in_memory`: [`parse`] refuses to choose the volatile store silently.
    pub data_dir: Option<PathBuf>,
    /// Keep everything in memory (all data and cursors are lost on exit).
    pub in_memory: bool,
    /// Fsync policy of the durable store.
    pub fsync: Fsync,
    /// Limits and CORS.
    pub config: Config,
}

/// What the command line asked for.
#[derive(Debug, Clone)]
pub enum Cli {
    /// Run the relay.
    Run(Box<Options>),
    /// Print [`USAGE`] and exit.
    Help,
    /// Print the version and exit.
    Version,
}

/// `--help` text. Every flag `--some-name` also reads `GSP_RELAY_SOME_NAME`;
/// a flag wins over the environment.
pub const USAGE: &str = "\
gsp-relay: GSP v0 reference relay (stores and forwards sealed items)

usage: gsp-relay [--flag value]...

Each flag can also be set through the environment variable shown.
A flag wins over the environment.

  --addr <ip:port>              GSP_RELAY_ADDR                    127.0.0.1:8787
  --data-dir <path>             GSP_RELAY_DATA_DIR                (required unless --in-memory)
  --in-memory                   GSP_RELAY_IN_MEMORY=1             off; keep nothing on disk, lose
                                                                  all data and cursors on exit
  --cors-origin <origin>        GSP_RELAY_CORS_ORIGIN             *
  --fsync <always|never>        GSP_RELAY_FSYNC                   always
  --max-item-bytes <n>          GSP_RELAY_MAX_ITEM_BYTES          262144
  --max-request-bytes <n>       GSP_RELAY_MAX_REQUEST_BYTES       1048576
  --max-push-items <n>          GSP_RELAY_MAX_PUSH_ITEMS          64
  --max-batch-items <n>         GSP_RELAY_MAX_BATCH_ITEMS         256
  --max-batch-bytes <n>         GSP_RELAY_MAX_BATCH_BYTES         1048576
  --fragment-quota-bytes <n>    GSP_RELAY_FRAGMENT_QUOTA_BYTES    67108864
  --total-quota-bytes <n>       GSP_RELAY_TOTAL_QUOTA_BYTES       4294967296
  --max-fragments <n>           GSP_RELAY_MAX_FRAGMENTS           4096
  --registration-token <secret> GSP_RELAY_REGISTRATION_TOKEN      (unset: open registration)
                                prefer the environment: flags show up in process listings
  --max-decode-bytes <n>        GSP_RELAY_MAX_DECODE_BYTES        8388608
  --max-polls-per-fragment <n>  GSP_RELAY_MAX_POLLS_PER_FRAGMENT  8
  --max-polls <n>               GSP_RELAY_MAX_POLLS               512
  --max-connections <n>         GSP_RELAY_MAX_CONNECTIONS         1024
  --read-timeout-ms <n>         GSP_RELAY_READ_TIMEOUT_MS         15000
  --shutdown-grace-ms <n>       GSP_RELAY_SHUTDOWN_GRACE_MS       10000
  --help, --version
";

const FLAGS: &[&str] = &[
    "addr",
    "data-dir",
    "cors-origin",
    "fsync",
    "max-item-bytes",
    "max-request-bytes",
    "max-push-items",
    "max-batch-items",
    "max-batch-bytes",
    "fragment-quota-bytes",
    "total-quota-bytes",
    "max-fragments",
    "registration-token",
    "max-decode-bytes",
    "in-memory",
    "max-polls-per-fragment",
    "max-polls",
    "max-connections",
    "read-timeout-ms",
    "shutdown-grace-ms",
];

/// Flags that take no value on the command line.
const BOOL_FLAGS: &[&str] = &["in-memory"];

fn truthy(flag: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("--{flag} ({}): expected 1 or 0", env_name(flag))),
    }
}

fn env_name(flag: &str) -> String {
    format!("GSP_RELAY_{}", flag.replace('-', "_").to_uppercase())
}

fn num<T: std::str::FromStr>(flag: &str, v: &str) -> Result<T, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("--{flag} ({}): not a valid number", env_name(flag)))
}

/// Parse flags (without the program name) on top of environment variables.
/// `env` looks one variable up; pass `|k| std::env::var(k).ok()`.
pub fn parse<I, S, E>(args: I, env: E) -> Result<Cli, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    E: Fn(&str) -> Option<String>,
{
    let mut given: Vec<(String, String)> = Vec::new();
    let mut it = args.into_iter().map(Into::into);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(Cli::Help),
            "--version" | "-V" => return Ok(Cli::Version),
            _ => {}
        }
        let Some(body) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument (see --help): {arg}"));
        };
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None if BOOL_FLAGS.contains(&body) => (body.to_string(), "true".to_string()),
            None => {
                let v = it.next().ok_or_else(|| format!("--{body} needs a value"))?;
                (body.to_string(), v)
            }
        };
        if !FLAGS.contains(&name.as_str()) {
            return Err(format!("unknown flag (see --help): --{name}"));
        }
        given.push((name, value));
    }
    let get = |flag: &str| -> Option<String> {
        given
            .iter()
            .rev()
            .find(|(n, _)| n == flag)
            .map(|(_, v)| v.clone())
            .or_else(|| env(&env_name(flag)).filter(|v| !v.is_empty()))
    };

    let mut o = Options {
        addr: SocketAddr::from(([127, 0, 0, 1], 8787)),
        data_dir: None,
        in_memory: false,
        fsync: Fsync::Always,
        config: Config::default(),
    };
    if let Some(v) = get("addr") {
        o.addr = v
            .trim()
            .parse()
            .map_err(|_| "--addr (GSP_RELAY_ADDR): expected ip:port".to_string())?;
    }
    o.data_dir = get("data-dir").map(PathBuf::from);
    if let Some(v) = get("in-memory") {
        o.in_memory = truthy("in-memory", &v)?;
    }
    match (&o.data_dir, o.in_memory) {
        (None, false) => {
            return Err(
                "no storage chosen. Give --data-dir <path> (GSP_RELAY_DATA_DIR) to keep \
                 items on disk, or --in-memory (GSP_RELAY_IN_MEMORY=1) to run without \
                 persistence: all items and cursors are then lost when the relay stops."
                    .into(),
            );
        }
        (Some(_), true) => {
            return Err("--data-dir and --in-memory exclude each other".into());
        }
        _ => {}
    }
    if let Some(v) = get("registration-token") {
        o.config.registration_token = Some(Secret::new(v));
    }
    if let Some(v) = get("cors-origin") {
        o.config.cors_origin = v;
    }
    if let Some(v) = get("fsync") {
        o.fsync = match v.trim() {
            "always" => Fsync::Always,
            "never" => Fsync::Never,
            _ => return Err("--fsync (GSP_RELAY_FSYNC): expected always or never".into()),
        };
    }
    let c = &mut o.config;
    macro_rules! set {
        ($flag:literal, $field:expr) => {
            if let Some(v) = get($flag) {
                $field = num($flag, &v)?;
            }
        };
    }
    set!("max-item-bytes", c.max_item_bytes);
    set!("max-request-bytes", c.max_request_bytes);
    set!("max-push-items", c.max_push_items);
    set!("max-batch-items", c.max_batch_items);
    set!("max-batch-bytes", c.max_batch_bytes);
    set!("fragment-quota-bytes", c.fragment_quota_bytes);
    set!("total-quota-bytes", c.total_quota_bytes);
    set!("max-fragments", c.max_fragments);
    set!("max-decode-bytes", c.max_decode_bytes);
    set!("max-polls-per-fragment", c.max_polls_per_fragment);
    set!("max-polls", c.max_polls);
    set!("max-connections", c.max_connections);
    if let Some(v) = get("read-timeout-ms") {
        c.read_timeout = Duration::from_millis(num("read-timeout-ms", &v)?);
    }
    if let Some(v) = get("shutdown-grace-ms") {
        c.shutdown_grace = Duration::from_millis(num("shutdown-grace-ms", &v)?);
    }
    o.config.validate()?;
    Ok(Cli::Run(Box::new(o)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: &[(&str, &str)]) -> Result<Cli, String> {
        parse(args.iter().copied(), |k| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        })
    }

    #[test]
    fn defaults_env_and_flag_precedence() {
        let Cli::Run(o) = run(&["--in-memory"], &[]).unwrap() else {
            panic!()
        };
        assert_eq!(o.addr.to_string(), "127.0.0.1:8787");
        assert!(o.data_dir.is_none() && o.in_memory);
        assert!(o.config.registration_token.is_none());
        assert_eq!(o.config.cors_origin, "*");
        assert_eq!(o.fsync, Fsync::Always);

        let env = [
            ("GSP_RELAY_ADDR", "0.0.0.0:9000"),
            ("GSP_RELAY_DATA_DIR", "/var/lib/gsp"),
            ("GSP_RELAY_CORS_ORIGIN", "https://app.example"),
            ("GSP_RELAY_MAX_POLLS_PER_FRAGMENT", "3"),
            ("GSP_RELAY_REGISTRATION_TOKEN", "s3cret-value"),
        ];
        let Cli::Run(o) = run(&["--addr", "127.0.0.1:1", "--max-polls=7"], &env).unwrap() else {
            panic!()
        };
        assert_eq!(o.addr.to_string(), "127.0.0.1:1");
        assert_eq!(
            o.data_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/gsp"))
        );
        assert_eq!(o.config.cors_origin, "https://app.example");
        assert_eq!(o.config.max_polls_per_fragment, 3);
        assert_eq!(o.config.max_polls, 7);
        assert!(!o.in_memory);
        let secret = o.config.registration_token.clone().unwrap();
        assert_eq!(secret.expose(), "s3cret-value");
        // The secret never appears in Debug output.
        assert!(!format!("{o:?}").contains("s3cret"));
    }

    #[test]
    fn storage_must_be_chosen_explicitly() {
        // Neither: refuse, and say what to do.
        let err = run(&[], &[]).unwrap_err();
        assert!(err.contains("--data-dir") && err.contains("--in-memory"));
        // Either one alone is fine, by flag or by environment.
        assert!(run(&["--data-dir", "/x"], &[]).is_ok());
        assert!(run(&["--in-memory"], &[]).is_ok());
        assert!(run(&["--in-memory=true"], &[]).is_ok());
        assert!(run(&[], &[("GSP_RELAY_IN_MEMORY", "1")]).is_ok());
        assert!(run(&[], &[("GSP_RELAY_IN_MEMORY", "0")]).is_err());
        assert!(run(&[], &[("GSP_RELAY_IN_MEMORY", "maybe")]).is_err());
        // Both: refuse.
        assert!(run(&["--data-dir", "/x", "--in-memory"], &[]).is_err());
        assert!(run(&["--in-memory"], &[("GSP_RELAY_DATA_DIR", "/x")]).is_err());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(run(&["--in-memory", "--nope", "1"], &[]).is_err());
        assert!(run(&["--in-memory", "positional"], &[]).is_err());
        assert!(run(&["--in-memory", "--addr"], &[]).is_err());
        assert!(run(&["--in-memory", "--addr", "localhost"], &[]).is_err());
        assert!(run(&["--in-memory", "--max-push-items", "-1"], &[]).is_err());
        assert!(run(&["--in-memory", "--max-push-items", "0"], &[]).is_err());
        assert!(run(&["--in-memory", "--fsync", "sometimes"], &[]).is_err());
        assert!(run(&["--in-memory", "--cors-origin", "bad\nvalue"], &[]).is_err());
        assert!(run(&["--in-memory"], &[("GSP_RELAY_MAX_FRAGMENTS", "many")]).is_err());
        assert!(run(&["--in-memory", "--registration-token", ""], &[]).is_err());
        assert!(run(&["--in-memory", "--max-decode-bytes", "10"], &[]).is_err());
        assert!(matches!(run(&["--help"], &[]), Ok(Cli::Help)));
        assert!(matches!(run(&["--version"], &[]), Ok(Cli::Version)));
    }
}
