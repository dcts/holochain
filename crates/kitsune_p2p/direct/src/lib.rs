//! Kitsune P2p Direct - Kitsune P2p Application Demo

#![forbid(unsafe_code)]
#![forbid(warnings)]
#![forbid(missing_docs)]

use actor::KitsuneP2pSender;
use arc_swap::*;
use futures::FutureExt;
use kitsune_p2p::dependencies::*;
use kitsune_p2p::*;
use kitsune_p2p_types::codec::Codec;
use kitsune_p2p_types::dependencies::*;
use std::collections::HashMap;
use std::sync::Arc;
use url2::*;

mod error;
pub use error::*;

mod kd_entry;
pub use kd_entry::*;

mod kd_actor;
pub use kd_actor::KdHash;

/// Events receivable by activated acting_agents
#[derive(Debug)]
pub enum KdEvent {
    /// Send a message to another agent
    Message {
        /// the root agent/space for the destination
        root_agent: KdHash,

        /// the active destination agent
        to_active_agent: KdHash,

        /// the active source agent
        from_active_agent: KdHash,

        /// the content of the message
        content: serde_json::Value,
    },
}

ghost_actor::ghost_chan! {
    /// Api for controlling Kitsune P2p Direct task
    pub chan KdApi<KdError> {
        /// List connection URLs
        fn list_transport_bindings() -> Vec<Url2>;

        /// Create a new signature agent for use with Kd
        fn generate_agent() -> KdHash;

        /// Sign data with internally managed private key associated
        /// with given pub key.
        fn sign(pub_key: KdHash, data: sodoken::Buffer) -> Arc<[u8; 64]>;

        /// Join space with given root agent / acting agent.
        /// The acting_agent will remain inactive until activated.
        fn join(root_agent: KdHash, acting_agent: KdHash) -> ();

        /// Activate a previously joined acting_agent
        fn activate(acting_agent: KdHash) -> tokio::sync::mpsc::Receiver<KdEvent>;

        /// Message an active agent
        fn message(
            root_agent: KdHash,
            from_active_agent: KdHash,
            to_active_agent: KdHash,
            content: serde_json::Value,
        ) -> ();
    }
}

/// Kitsune P2p Direct Sender Type
pub type KdSender = ghost_actor::GhostSender<KdApi>;

/// Kitsune P2p Direct Config
/// Most Kd config lives in the live persistance store,
/// but, to bootstrap, we need two things:
/// - the store path (or None if we shouldn't persist - i.e. for testing)
/// - the unlock passphrase to use for encrypting / decrypting persisted data
pub struct KdConfig {
    /// Where to store the Kd persistence data on disk
    /// (None to not persist - will keep in memory - be wary of mem usage)
    pub persist_path: Option<std::path::PathBuf>,

    /// User supplied passphrase for encrypting persistance
    /// USE `sodoken::Buffer::new_memlocked()` TO KEEP SECURE!
    pub unlock_passphrase: sodoken::Buffer,

    /// Example directives:
    /// - "set_proxy_accept_all:"
    /// - "bind_mem_local:"
    /// - "bind_quic_local:kitsune-quic://0.0.0.0:0"
    /// - "bind_quic_proxy:kitsune-proxy://YADA.."
    pub directives: Vec<String>,
}

/// spawn a Kitsune P2p Direct actor
pub async fn spawn_kitsune_p2p_direct(config: KdConfig) -> KdResult<KdSender> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();
    let channel_factory = builder.channel_factory().clone();
    let sender = channel_factory.create_channel::<KdApi>().await?;
    tokio::task::spawn(builder.spawn(kd_actor::KdActor::new(config, channel_factory).await?));
    Ok(sender)
}

#[cfg(test)]
mod test;
