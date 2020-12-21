//! Kitsune P2p Direct - Kitsune P2p Application Demo

#![forbid(unsafe_code)]
#![forbid(warnings)]
#![forbid(missing_docs)]

use actor::KitsuneP2pSender;
use arc_swap::*;
use futures::FutureExt;
use kitsune_p2p::dependencies::*;
use kitsune_p2p::*;
use kitsune_p2p_types::dependencies::*;
use std::sync::Arc;
use std::collections::HashMap;
use url2::*;

mod error;
pub use error::*;

mod kd_entry;
pub use kd_entry::*;

mod kd_actor;
pub use kd_actor::KdHash;

ghost_actor::ghost_chan! {
    /// Api for controlling Kitsune P2p Direct task
    pub chan KdApi<KdError> {
        /// Spawns a kitsune p2p node with given config directives.
        ///
        /// Example directives:
        /// - "set_proxy_accept_all:"
        /// - "bind_mem_local:"
        /// - "bind_quic_local:kitnuse-quic://0.0.0.0:0"
        /// - "bind_quic_proxy:kitsune-poxy://YADA.."
        fn create_kitsune(config_directives: Vec<String>) -> ();

        /// List connection URLs
        fn list_connection_urls() -> Vec<Url2>;

        /// Create a new signature agent for use with Kd
        fn generate_agent() -> KdHash;

        /// Sign data with internally managed private key associated
        /// with given pub key.
        fn sign(pub_key: KdHash, data: sodoken::Buffer) -> Arc<[u8; 64]>;
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
