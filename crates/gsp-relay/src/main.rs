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
    let relay = match &o.data_dir {
        Some(dir) => Relay::new(o.config.clone(), DirStore::open(dir, o.fsync)?)?,
        None => Relay::new(o.config.clone(), MemStore::new())?,
    };
    let listener = tokio::net::TcpListener::bind(o.addr).await?;
    eprintln!(
        "gsp-relay {} listening on http://{} store={} cors_origin={}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?,
        match &o.data_dir {
            Some(dir) => format!("dir:{} fsync={:?}", dir.display(), o.fsync),
            None => "memory (items are lost on exit; set --data-dir to keep them)".into(),
        },
        o.config.cors_origin,
    );
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
