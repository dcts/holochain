use super::*;
use std::collections::HashMap;

ghost_actor::ghost_chan! {
    pub(crate) chan PersistApi<KdError> {
        fn store_sign_pair(pk: KdHash, sk: sodoken::Buffer) -> ();
        fn get_sign_secret(pk: KdHash) -> sodoken::Buffer;
    }
}

pub(crate) type PersistSender = ghost_actor::GhostSender<PersistApi>;

pub(crate) async fn spawn_persist() -> KdResult<PersistSender> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<PersistApi>()
        .await?;

    tokio::task::spawn(builder.spawn(Persist::new()));

    Ok(sender)
}

struct Persist {
    sign_pairs: HashMap<KdHash, sodoken::Buffer>,
}

impl Persist {
    pub fn new() -> Self {
        Self {
            sign_pairs: HashMap::new(),
        }
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
        self.sign_pairs.insert(pk, sk);
        Ok(async move { Ok(()) }.boxed().into())
    }

    fn handle_get_sign_secret(&mut self, pk: KdHash) -> PersistApiHandlerResult<sodoken::Buffer> {
        match self.sign_pairs.get(&pk) {
            Some(sk) => {
                let sk = sk.clone();
                Ok(async move { Ok(sk) }.boxed().into())
            }
            None => Err("invalid pub key".into()),
        }
    }
}
