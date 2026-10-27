use crate::server::{self, ServerConfig};
use anyhow::Result;

/// Run the selected server with process signal handling.
///
/// # Errors
/// Returns signal registration, configuration, listener, and server failures.
pub async fn execute(config: ServerConfig) -> Result<()> {
    server::run(config, server::shutdown_signal()?).await
}
