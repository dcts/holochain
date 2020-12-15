//! Kitsune P2p Direct - Kitsune P2p Application Demo

#![forbid(unsafe_code)]
#![forbid(warnings)]
#![forbid(missing_docs)]

use std::sync::Arc;
use kitsune_p2p::*;
use actor::KitsuneP2pSender;
use kitsune_p2p::dependencies::*;
use kitsune_p2p_types::dependencies::*;
use futures::FutureExt;
use url2::*;

mod error;
pub use error::*;

mod kd_entry;
pub use kd_entry::*;

mod kd_actor;

ghost_actor::ghost_chan! {
    /// Api for controlling Kitsune P2p Direct task
    pub chan KdApi<KdError> {
        /// Spawns a memory-based (local-only) kitsune instance
        /// into the Kd actor.
        fn create_kitsune_mem() -> ();
    }
}

/// Kitsune P2p Direct Sender Type
pub type KdSender = ghost_actor::GhostSender<KdApi>;

/// spawn a Kitsune P2p Direct actor
pub async fn spawn_kitsune_p2p_direct() -> KdResult<KdSender> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();
    let channel_factory = builder.channel_factory().clone();
    let sender = channel_factory.create_channel::<KdApi>().await?;
    tokio::task::spawn(builder.spawn(kd_actor::KdActor::new(
        channel_factory,
    ).await?));
    Ok(sender)
}

#[cfg(test)]
mod test;
