use super::*;
use rusqlite::*;

ghost_actor::ghost_chan! {
    pub(crate) chan PersistApi<KdError> {
        fn store_sign_pair(pk: KdHash, sk: sodoken::Buffer) -> ();
        fn get_sign_secret(pk: KdHash) -> sodoken::Buffer;
    }
}

pub(crate) type PersistSender = ghost_actor::GhostSender<PersistApi>;

pub(crate) async fn spawn_persist(config: KdConfig) -> KdResult<PersistSender> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<PersistApi>()
        .await?;

    tokio::task::spawn(builder.spawn(Persist::new(config).await?));

    Ok(sender)
}

struct Persist {
    con: Connection,
}

const KEY_PRAGMA_LEN: usize = 83;
const KEY_PRAGMA: &[u8; KEY_PRAGMA_LEN] =
    br#"PRAGMA key = "x'0000000000000000000000000000000000000000000000000000000000000000'";"#;

/// write a sqlcipher key pragma maintaining mem protection
async fn secure_write_key_pragma(passphrase: &sodoken::Buffer) -> KdResult<sodoken::Buffer> {
    // first, hash the passphrase
    let mut key_buf = sodoken::Buffer::new_memlocked(32)?;
    sodoken::hash::generichash(&mut key_buf, &passphrase, None).await?;

    // now write the pragma line
    let key_pragma = sodoken::Buffer::new_memlocked(KEY_PRAGMA_LEN)?;

    {
        use std::io::Write;
        let mut key_pragma = key_pragma.write_lock();
        key_pragma.copy_from_slice(KEY_PRAGMA);
        let mut c = std::io::Cursor::new(&mut key_pragma[16..80]);
        for b in &*key_buf.read_lock() {
            write!(c, "{:02X}", b).map_err(KdError::other)?;
        }
    }

    Ok(key_pragma)
}

impl Persist {
    pub async fn new(config: KdConfig) -> KdResult<Self> {
        let con = Connection::open(match config.persist_path {
            Some(p) => p,
            None => std::path::Path::new(":memory:").to_path_buf(),
        })?;

        // set encryption key
        let key_pragma = secure_write_key_pragma(&config.unlock_passphrase).await?;
        con.execute(
            std::str::from_utf8(&*key_pragma.read_lock()).unwrap(),
            NO_PARAMS,
        )?;

        // set to faster write-ahead-log mode
        con.pragma_update(None, "journal_mode", &"WAL".to_string())?;

        // create the private key table
        con.execute(
            "CREATE TABLE IF NOT EXISTS sign_keypairs (
                pub_key       BLOB PRIMARY KEY,
                sec_key       BLOB NOT NULL
            );",
            NO_PARAMS,
        )?;

        Ok(Self { con })
    }

    pub fn insert_keypair(&mut self, pk: KdHash, sk: sodoken::Buffer) -> KdResult<()> {
        let tx = self.con.transaction()?;

        {
            let mut ins =
                tx.prepare_cached("INSERT INTO sign_keypairs (pub_key, sec_key) VALUES (?1, ?2);")?;

            // TODO - the same dance we did with the encryption key above
            ins.execute(params![&pk.get_hash_bytes()[..], &*sk.read_lock()])?;
        }

        tx.commit()?;

        Ok(())
    }

    pub fn query_keypair(&mut self, pk: &KdHash) -> KdResult<sodoken::Buffer> {
        let buffer = sodoken::Buffer::new_memlocked(64)?;
        self.con.query_row(
            "SELECT sec_key FROM sign_keypairs WHERE pub_key = ?1 LIMIT 1;",
            params![&pk.get_hash_bytes()[..]],
            |row| {
                // TODO - how do we make sure this stays secure??
                if let types::ValueRef::Blob(b) = row.get_raw(0) {
                    buffer.write_lock().copy_from_slice(b);
                    Ok(())
                } else {
                    Err(Error::ToSqlConversionFailure(Box::new(KdError::from(
                        "bad type",
                    ))))
                }
            },
        )?;
        Ok(buffer)
    }
}

impl ghost_actor::GhostControlHandler for Persist {}

impl ghost_actor::GhostHandler<PersistApi> for Persist {}

impl PersistApiHandler for Persist {
    fn handle_store_sign_pair(
        &mut self,
        pk: KdHash,
        sk: sodoken::Buffer,
    ) -> PersistApiHandlerResult<()> {
        self.insert_keypair(pk, sk)?;
        Ok(async move { Ok(()) }.boxed().into())
    }

    fn handle_get_sign_secret(&mut self, pk: KdHash) -> PersistApiHandlerResult<sodoken::Buffer> {
        let sk = self.query_keypair(&pk)?;
        Ok(async move { Ok(sk) }.boxed().into())
    }
}
