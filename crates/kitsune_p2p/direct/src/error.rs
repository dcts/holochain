//! Kd Error types

use crate::*;

/// Error related to remote communication.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdError {
    /// GhostError.
    #[error(transparent)]
    GhostError(#[from] ghost_actor::GhostError),

    /// Unspecified error.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl KdError {
    /// promote a custom error type to a KdError
    pub fn other(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Other(e.into())
    }
}

impl From<KitsuneP2pError> for KdError {
    fn from(e: KitsuneP2pError) -> Self {
        KdError::other(e)
    }
}

impl From<String> for KdError {
    fn from(s: String) -> Self {
        #[derive(Debug, thiserror::Error)]
        struct OtherError(String);
        impl std::fmt::Display for OtherError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        KdError::other(OtherError(s))
    }
}

impl From<&str> for KdError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<KdError> for () {
    fn from(_: KdError) {}
}

/// Result type for remote communication.
pub type KdResult<T> = Result<T, KdError>;
