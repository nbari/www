use crate::server::ServerConfig;

pub mod serve;

/// The contract between argument dispatch and execution.
#[derive(Debug)]
pub enum Action {
    Serve(ServerConfig),
    ServeBound(ServerConfig, std::net::IpAddr),
}
