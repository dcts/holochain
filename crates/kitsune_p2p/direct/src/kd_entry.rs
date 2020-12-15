//! Kitsune P2p Direct one entry to rule them all

use crate::*;
use byteorder::{LittleEndian, ReadBytesExt};

/// sys_type enum
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysType {
    /// imaginary origin type - no data should actually contain this sys_type
    Origin = 0x00,

    /// hot spot mitigator
    HSM = 0x01,

    /// validation
    Validation = 0x02,

    /// user interface
    UI = 0x03,

    /// authorization
    Auth = 0x10,

    /// app node create
    Create = 0x20,

    /// delete
    Delete = 0x21,
}

impl From<u8> for SysType {
    fn from(b: u8) -> Self {
        match b {
            0x00 => SysType::Origin,
            _ => panic!("invalid sys_type byte"),
        }
    }
}

/// Kitsune P2p Direct one entry to rule them all
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdEntry(Arc<Vec<u8>>);

impl From<Vec<u8>> for KdEntry {
    fn from(v: Vec<u8>) -> Self {
        Self(Arc::new(v))
    }
}

impl From<Arc<Vec<u8>>> for KdEntry {
    fn from(v: Arc<Vec<u8>>) -> Self {
        Self(v)
    }
}

impl std::ops::Deref for KdEntry {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for KdEntry {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for KdEntry {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

const SIG_START: usize = 4;
const SIG_LEN: usize = 64;
const SYS_TYPE_START: usize = 69;
const CREATE_START: usize = 70;
const CREATE_LEN: usize = 8;
const EXPIRE_START: usize = 78;
const EXPIRE_LEN: usize = 8;
const AUTHOR_START: usize = 86;
const AUTHOR_LEN: usize = 36;
const LEFT_LINK_START: usize = 122;
const LEFT_LINK_LEN: usize = 36;
const RIGHT_LINK_START: usize = 158;
const RIGHT_LINK_LEN: usize = 36;
const USER_TYPE_START: usize = 194;
const USER_TYPE_LEN: usize = 32;
const CONTENT_START: usize = 226;

impl KdEntry {
    /// size/length of underlying raw bytes
    pub fn size(&self) -> u32 {
        self.0.len() as u32
    }

    /// signature bytes
    pub fn signature(&self) -> &[u8; SIG_LEN] {
        arrayref::array_ref![self.0, SIG_START, SIG_LEN]
    }

    /// sys_type
    pub fn sys_type(&self) -> SysType {
        self.0[SYS_TYPE_START].into()
    }

    /// create time in epoch millis
    pub fn create_epoch_ms(&self) -> u64 {
        (&self.0[CREATE_START..CREATE_START + CREATE_LEN])
            .read_u64::<LittleEndian>()
            .unwrap()
    }

    /// expire time in epoch millis
    pub fn expire_epoch_ms(&self) -> u64 {
        (&self.0[EXPIRE_START..EXPIRE_START + EXPIRE_LEN])
            .read_u64::<LittleEndian>()
            .unwrap()
    }

    /// author
    pub fn author(&self) -> &[u8; AUTHOR_LEN] {
        arrayref::array_ref![self.0, AUTHOR_START, AUTHOR_LEN]
    }

    /// left_link
    pub fn left_link(&self) -> &[u8; LEFT_LINK_LEN] {
        arrayref::array_ref![self.0, LEFT_LINK_START, LEFT_LINK_LEN]
    }

    /// right_link
    pub fn right_link(&self) -> &[u8; RIGHT_LINK_LEN] {
        arrayref::array_ref![self.0, RIGHT_LINK_START, RIGHT_LINK_LEN]
    }

    /// user_type
    pub fn user_type(&self) -> &[u8; USER_TYPE_LEN] {
        arrayref::array_ref![self.0, USER_TYPE_START, USER_TYPE_LEN]
    }

    /// content
    pub fn content(&self) -> &[u8] {
        &self.0[CONTENT_START..]
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn sanity() {}
}
