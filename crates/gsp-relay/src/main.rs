//! `gsp-relay` binary: parse flags/env, open the store, serve until
//! SIGINT or SIGTERM.
#![forbid(unsafe_code)]

use gsp_relay::config::{Cli, Options, USAGE, parse};
use gsp_relay::{DirStore, MemStore, Relay, serve};
use std::process::ExitCode;

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

async fn run(o: Options) -> std::io::Result<()> {
    let (relay, store) = match &o.data_dir {
        Some(dir) => (
            Relay::new(o.config.clone(), DirStore::open(dir, o.fsync)?)?,
            format!("dir:{} fsync={:?}", dir.display(), o.fsync),
        ),
        None => (
            Relay::new(o.config.clone(), MemStore::new())?,
            "memory".to_string(),
        ),
    };
    let listener = tokio::net::TcpListener::bind(o.addr).await?;
    eprintln!(
        "gsp-relay {} listening on http://{} store={store} cors_origin={} registration={}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?,
        o.config.cors_origin,
        if o.config.registration_token.is_some() {
            "secret-required"
        } else {
            "open"
        },
    );
    if o.data_dir.is_none() {
        eprintln!(
            "gsp-relay: WARNING: running --in-memory. Every item, token registration and \
             cursor is lost when this process stops; clients will then see the relay \
             restart numbering from 1."
        );
    } else if o.fsync == gsp_relay::Fsync::Never {
        eprintln!(
            "gsp-relay: WARNING: --fsync never. Items acknowledged shortly before an OS \
             crash or power loss can be lost, and their cursors reused."
        );
    }
    if o.config.registration_token.is_none() {
        eprintln!(
            "gsp-relay: note: registration is open. Anyone who can reach this relay can \
             register fragments until its quotas are used up; set \
             GSP_RELAY_REGISTRATION_TOKEN or restrict access in front of it."
        );
    }
    serve(listener, relay, shutdown_signal()).await
}

fn main() -> ExitCode {
    // Command-line flags only; the program name (argv[0]) is skipped and
    // nothing here is a security decision.
    // nosemgrep: rust.lang.security.args.args
    let options = match parse(std::env::args().skip(1), |k| std::env::var(k).ok()) {
        Ok(Cli::Run(o)) => *o,
        Ok(Cli::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Version) => {
            println!("gsp-relay {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("gsp-relay: {e}");
            return ExitCode::from(2);
        }
    };
    gsp_relay::log::set_enabled(true);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("gsp-relay: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gsp-relay: {e}");
            ExitCode::FAILURE
        }
    }
}
