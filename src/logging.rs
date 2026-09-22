//! Tracing subscriber initialization with optional file output.
//!
//! `init_tracing` sets up a global `tracing` subscriber that writes to stdout
//! and, when a log file path is provided, *also* to that file. The file is
//! opened in append mode; its parent directory is created if necessary.
//!
//! Filter priority (highest to lowest):
//! 1. `RUST_LOG` environment variable (if set)
//! 2. `log_level` argument (from config file or `--log-level`)
//! 3. `"info"` (built-in default)
//!
//! If the log file cannot be opened, a warning is printed to stderr and
//! stdout-only logging continues — the daemon never refuses to start solely
//! because of a logging configuration problem.

use std::path::Path;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Initialize the global tracing subscriber with the given filter and optional
/// file output.
///
/// `log_level` is a `RUST_LOG`-style filter string (e.g. `"info"`, `"debug"`,
/// `"warn"`, `"error"`, `"trace"`, or `"rustnies::tunnel=trace"`). It is used
/// only when `RUST_LOG` is not already set in the environment.
///
/// `log_file`, when set, causes log lines to be written to both stdout and the
/// file (in append mode). The parent directory is created if missing.
pub fn init_tracing(log_level: Option<&str>, log_file: Option<&Path>) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(v) => EnvFilter::new(v),
        Err(_) => EnvFilter::new(log_level.unwrap_or("info")),
    };

    let stdout_layer = fmt::layer();

    match log_file {
        Some(path) => {
            // Best-effort: create the parent directory if it doesn't exist.
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let filename = path
                .file_name()
                .map(std::ffi::OsString::from)
                .unwrap_or_else(|| std::ffi::OsString::from("rustnies.log"));

            // `rolling::never` opens the file immediately; if it fails (e.g.
            // permission denied), fall back to stdout-only with a warning.
            match std::panic::catch_unwind(|| tracing_appender::rolling::never(dir, &filename)) {
                Ok(file_appender) => {
                    let file_layer = fmt::layer().with_writer(file_appender);
                    let _ = tracing_subscriber::registry()
                        .with(filter)
                        .with(stdout_layer)
                        .with(file_layer)
                        .try_init();
                }
                Err(_) => {
                    eprintln!(
                        "failed to open log file {}; logging to stdout only",
                        path.display()
                    );
                    let _ = tracing_subscriber::registry()
                        .with(filter)
                        .with(stdout_layer)
                        .try_init();
                }
            }
        }
        None => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .try_init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_without_file_does_not_panic() {
        init_tracing(Some("info"), None);
    }

    #[test]
    fn init_tracing_with_file_creates_file() {
        let dir = std::env::temp_dir().join(format!(
            "rustnies-log-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("init_tracing_test.log");
        init_tracing(None, Some(&log_path));
        assert!(log_path.exists(), "log file should be created on init");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_tracing_falls_back_on_unwritable_path() {
        // Use a path whose parent is a regular file, so the directory cannot
        // be created and the file cannot be opened. init_tracing should
        // silently fall back to stdout-only instead of panicking.
        let tmp = std::env::temp_dir().join(format!(
            "rustnies-blocker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::File::create(&tmp).unwrap();
        let bad = tmp.join("sub/log.log");
        init_tracing(None, Some(&bad));
        let _ = std::fs::remove_file(&tmp);
    }
}
