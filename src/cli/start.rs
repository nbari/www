use crate::cli::{actions::Action, commands, dispatch, telemetry};
use anyhow::Result;

/// Parse, initialize local logging, and return the action to the binary.
///
/// # Errors
/// Returns logging initialization or argument dispatch failures.
pub fn start() -> Result<Action> {
    let matches = commands::new().get_matches();
    telemetry::init(matches.get_flag("quiet"))?;
    dispatch::handler(&matches)
}
