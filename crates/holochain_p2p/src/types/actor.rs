//! Module containing the HolochainP2p actor definition.

use crate::*;

/// The p2p module must be informed at runtime which dna/agent pairs it should be tracking.
pub struct Join {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
}

/// If a cell is deactivated, we'll need to "leave" the network module as well.
pub struct Leave {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
}

/// Invoke a zome function on a remote node (if you have been granted the capability).
pub struct CallRemote {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
    // TODO - parameters
}

/// Publish data to the correct neigborhood.
pub struct Publish {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
    // TODO - parameters
}

/// Request a validation package.
pub struct GetValidationPackage {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
    // TODO - parameters
}

/// Get an entry from the DHT.
pub struct Get {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
    // TODO - parameters
}

/// Get links from the DHT.
pub struct GetLinks {
    /// The dna_hash / space_hash context.
    pub dna_hash: DnaHash,
    /// The agent_id / agent_pub_key context.
    pub agent_pub_key: AgentPubKey,
    // TODO - parameters
}

ghost_actor::ghost_actor! {
    Visibility(pub),
    Name(HolochainP2p),
    Error(HolochainP2pError),
    Api {
        Join(
            "The p2p module must be informed at runtime which dna/agent pairs it should be tracking.",
            Join,
            (),
        ),
        Leave(
            "If a cell is deactivated, we'll need to \"leave\" the network module as well.",
            Leave,
            (),
        ),
        CallRemote(
            "Invoke a zome function on a remote node (if you have been granted the capability).",
            CallRemote,
            (), // TODO - proper return type
        ),
        Publish(
            "Publish data to the correct neigborhood.",
            Publish,
            (), // TODO - proper return type
        ),
        GetValidationPackage(
            "Request a validation package.",
            GetValidationPackage,
            (), // TODO - proper return type
        ),
        Get(
            "Get an entry from the DHT.",
            Get,
            (), // TODO - proper return type
        ),
        GetLinks(
            "Get links from the DHT.",
            GetLinks,
            (), // TODO - proper return type
        ),
    }
}