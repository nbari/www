//! CLI definitions, dispatch, execution, and local logging.

pub mod actions;
pub mod commands;
pub mod dispatch;
pub mod telemetry;

mod start;
pub use start::start;
