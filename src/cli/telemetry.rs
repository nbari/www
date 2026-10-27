use anyhow::Result;
use tracing::level_filters::LevelFilter;

/// Quiet mode suppresses informational output while keeping actionable errors visible.
///
/// # Errors
/// Returns an error if a subscriber is already installed or logging setup fails.
pub fn init(quiet: bool) -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(if quiet {
            LevelFilter::ERROR
        } else {
            LevelFilter::INFO
        })
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init()
        .map_err(|error| anyhow::anyhow!("cannot initialize logging: {error}"))
}
