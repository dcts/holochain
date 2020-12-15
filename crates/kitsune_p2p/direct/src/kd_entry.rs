//! Kitsune P2p Direct one entry to rule them all

use crate::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;

fn epoch_ms_to_chrono(epoch_ms: u64) -> DateTime<Utc> {
    let epoch = DateTime::from_utc(
        NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
        Utc,
    );
    let duration = chrono::Duration::from_std(
        std::time::Duration::from_millis(epoch_ms)
    ).unwrap();
    epoch + duration
}

fn chrono_to_epoch_ms(d: DateTime<Utc>) -> u64 {
    let epoch = DateTime::from_utc(
        NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
        Utc,
    );
    (d - epoch).to_std().unwrap().as_millis() as u64
}

macro_rules! _repr_enum {
    (#[doc = $ndoc:literal] pub enum $n:ident {
        $(#[doc = $idoc:literal] $i:ident = $l:literal,)*
    }) => {
        #[doc = $ndoc]
        #[repr(u8)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $n {$(
            #[doc = $idoc]
            $i = $l,
        )*}

        impl From<u8> for SysType {
            fn from(b: u8) -> Self {
                match b {$(
                    $l => SysType::$i,
                )*
                    _ => panic!("invalid sys_type byte"),
                }
            }
        }

        impl From<SysType> for u8 {
            fn from(s: SysType) -> Self {
                s as u8
            }
        }
    };
}

_repr_enum! {
    /// sys_type enum
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

const SIZE_START: usize = 0;
const SIZE_LEN: usize = 4;
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

macro_rules! _impl_getters {
    ($i:ident) => {
        impl $i {
            /// size/length of underlying raw bytes
            pub fn size(&self) -> u32 {
                self.0.len() as u32
            }

            /// the content portion used for signatures / hashing
            pub fn sig_content(&self) -> &[u8] {
                &self.0[SYS_TYPE_START..]
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
            pub fn create(&self) -> DateTime<Utc> {
                let ms = (&self.0[CREATE_START..CREATE_START + CREATE_LEN])
                    .read_u64::<LittleEndian>()
                    .unwrap();
                epoch_ms_to_chrono(ms)
            }

            /// expire time in epoch millis
            pub fn expire(&self) -> DateTime<Utc> {
                let ms = (&self.0[EXPIRE_START..EXPIRE_START + EXPIRE_LEN])
                    .read_u64::<LittleEndian>()
                    .unwrap();
                epoch_ms_to_chrono(ms)
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
    };
}

impl KdEntry {
    /// create a new builder for KdEntry instances
    pub fn builder() -> KdEntryBuilder {
        KdEntryBuilder::default()
    }
}

_impl_getters!(KdEntry);

/// Builder for KdEntry struct instances
pub struct KdEntryBuilder(Vec<u8>);

impl Default for KdEntryBuilder {
    fn default() -> Self {
        Self(vec![0; CONTENT_START])
    }
}

_impl_getters!(KdEntryBuilder);

impl KdEntryBuilder {
    /// convert this builder into a KdEntry instance
    pub fn build(self) -> KdEntry {
        // TODO Validation / size setting, etc
        KdEntry(Arc::new(self.0))
    }

    /// set the signature data of this instance
    pub fn set_signature(mut self, signature: &[u8; SIG_LEN]) -> Self {
        self
            .0[SIG_START..SIG_START+SIG_LEN]
            .copy_from_slice(signature);
        self
    }

    /// set the sys_type of this instance
    pub fn set_sys_type(mut self, sys_type: SysType) -> Self {
        self.0[SYS_TYPE_START] = sys_type as u8;
        self
    }

    /// set the create data of this instance
    pub fn set_create(mut self, create: DateTime<Utc>) -> Self {
        let ms = chrono_to_epoch_ms(create);
        (&mut self.0[CREATE_START..CREATE_START + CREATE_LEN])
            .write_u64::<LittleEndian>(ms)
            .unwrap();
        self
    }

    /// set the expire data of this instance
    pub fn set_expire(mut self, expire: DateTime<Utc>) -> Self {
        let ms = chrono_to_epoch_ms(expire);
        (&mut self.0[EXPIRE_START..EXPIRE_START + EXPIRE_LEN])
            .write_u64::<LittleEndian>(ms)
            .unwrap();
        self
    }

    /// set the author data of this instance
    pub fn set_author(mut self, author: &[u8; AUTHOR_LEN]) -> Self {
        self
            .0[AUTHOR_START..AUTHOR_START+AUTHOR_LEN]
            .copy_from_slice(author);
        self
    }

    /// set the left_link data of this instance
    pub fn set_left_link(mut self, left_link: &[u8; LEFT_LINK_LEN]) -> Self {
        self
            .0[LEFT_LINK_START..LEFT_LINK_START+LEFT_LINK_LEN]
            .copy_from_slice(left_link);
        self
    }

    /// set the right_link data of this instance
    pub fn set_right_link(mut self, right_link: &[u8; RIGHT_LINK_LEN]) -> Self {
        self
            .0[RIGHT_LINK_START..RIGHT_LINK_START+RIGHT_LINK_LEN]
            .copy_from_slice(right_link);
        self
    }

    /// set the user_type data of this instance
    pub fn set_user_type(mut self, user_type: &[u8; USER_TYPE_LEN]) -> Self {
        self
            .0[USER_TYPE_START..USER_TYPE_START+USER_TYPE_LEN]
            .copy_from_slice(user_type);
        self
    }

    /// set the content for this instance
    pub fn set_content(mut self, content: &[u8]) -> Self {
        self.0.truncate(CONTENT_START);
        self.0.extend_from_slice(content);
        let size = self.0.len() as u32;
        (&mut self.0[SIZE_START..SIZE_START + SIZE_LEN])
            .write_u32::<LittleEndian>(size)
            .unwrap();
        self
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn sanity() {}
}
