use crate::*;

mod persist;
use persist::*;

mod keystore;
pub use keystore::KdHash;
use keystore::*;

mod wire;
use wire::*;

pub(crate) struct KdActor {
    #[allow(dead_code)]
    i_s: ghost_actor::GhostSender<Internal>,
    persist: PersistSender,
    keystore: KeystoreSender,
    binding: ghost_actor::GhostSender<actor::KitsuneP2p>,
    active: HashMap<KdHash, tokio::sync::mpsc::Sender<KdEvent>>,
}

impl ghost_actor::GhostControlHandler for KdActor {}

impl KdActor {
    pub async fn new(
        config: KdConfig,
        channel_factory: ghost_actor::actor_builder::GhostActorChannelFactory<Self>,
    ) -> KdResult<Self> {
        let (p2p, evt) = spawn_p2p(&config.directives).await?;
        channel_factory.attach_receiver(evt).await?;

        let i_s = channel_factory.create_channel::<Internal>().await?;
        let persist = spawn_persist(config).await?;
        let keystore = spawn_keystore(persist.clone()).await?;

        Ok(KdActor {
            i_s,
            persist,
            keystore,
            binding: p2p,
            active: HashMap::new(),
        })
    }
}

#[allow(clippy::ptr_arg)]
async fn spawn_p2p(
    config_directives: &Vec<String>,
) -> KdResult<(
    ghost_actor::GhostSender<actor::KitsuneP2p>,
    futures::channel::mpsc::Receiver<event::KitsuneP2pEvent>,
)> {
    let mut should_proxy = false;
    let mut bind_mem_local = false;

    for d in config_directives.iter() {
        match &d as &str {
            "set_proxy_accept_all:" => should_proxy = true,
            "bind_mem_local:" => bind_mem_local = true,
            _ => {
                return Err(format!("invalid config directive: {}", d).into());
            }
        }
    }

    let mut config = KitsuneP2pConfig::default();

    let proxy = if should_proxy {
        Some(ProxyAcceptConfig::AcceptAll)
    } else {
        Some(ProxyAcceptConfig::RejectAll)
    };

    if bind_mem_local {
        config.transport_pool.push(TransportConfig::Proxy {
            sub_transport: Box::new(TransportConfig::Mem {}),
            proxy_config: ProxyConfig::LocalProxyServer {
                proxy_accept_config: proxy,
            },
        });
    }

    Ok(spawn_kitsune_p2p(
        config,
        kitsune_p2p_proxy::TlsConfig::new_ephemeral().await.unwrap(),
    )
    .await?)
}

ghost_actor::ghost_chan! {
    chan Internal<KdError> {
        fn stub() -> ();
    }
}

impl ghost_actor::GhostHandler<Internal> for KdActor {}

impl InternalHandler for KdActor {
    fn handle_stub(&mut self) -> InternalHandlerResult<()> {
        unimplemented!()
    }
}

impl ghost_actor::GhostHandler<event::KitsuneP2pEvent> for KdActor {}

impl event::KitsuneP2pEventHandler for KdActor {
    fn handle_put_agent_info_signed(
        &mut self,
        input: event::PutAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<()> {
        let event::PutAgentInfoSignedEvt {
            space,
            agent: _,
            agent_info_signed,
        } = input;
        let space: KdHash = space.into();
        let fut = self.persist.store_agent_info(space, agent_info_signed);
        Ok(async move { Ok(fut.await?) }.boxed().into())
    }

    fn handle_get_agent_info_signed(
        &mut self,
        input: event::GetAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Option<agent_store::AgentInfoSigned>> {
        let event::GetAgentInfoSignedEvt { space, agent } = input;
        let space: KdHash = space.into();
        let agent: KdHash = agent.into();
        let fut = self.persist.get_agent_info(space, agent);
        Ok(async move {
            Ok(match fut.await {
                Ok(i) => Some(i),
                Err(_) => None,
            })
        }
        .boxed()
        .into())
    }

    fn handle_query_agent_info_signed(
        &mut self,
        input: event::QueryAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<agent_store::AgentInfoSigned>> {
        let event::QueryAgentInfoSignedEvt { space, agent: _ } = input;
        let space: KdHash = space.into();
        let fut = self.persist.query_agent_info(space);
        Ok(async move { Ok(fut.await?) }.boxed().into())
    }

    fn handle_call(
        &mut self,
        space: Arc<KitsuneSpace>,
        to_agent: Arc<KitsuneAgent>,
        from_agent: Arc<KitsuneAgent>,
        payload: Vec<u8>,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<u8>> {
        let to_active_agent = KdHash::from(to_agent);
        let mut send = match self.active.get(&to_active_agent) {
            Some(send) => send.clone(),
            None => {
                return Ok(
                    async move { Ok(Wire::failure("no active agent".to_string()).encode_vec()?) }
                        .boxed()
                        .into(),
                )
            }
        };

        Ok(async move {
            let res: KdResult<()> = async move {
                let root_agent = KdHash::from(space);
                let from_active_agent = KdHash::from(from_agent);
                let (_, content) = Wire::decode_ref(&payload)?;
                let content = match content {
                    Wire::Message(Message { content }) => Ok(content),
                    _ => Err(KdError::from("invalid message")),
                }?;
                let evt = KdEvent::Message {
                    root_agent,
                    to_active_agent,
                    from_active_agent,
                    content,
                };
                send.send(evt).await.map_err(KdError::other)?;
                Ok(())
            }
            .await;

            if let Err(e) = res {
                Ok(Wire::failure(format!("{:?}", e)).encode_vec()?)
            } else {
                Ok(Wire::success().encode_vec()?)
            }
        }
        .boxed()
        .into())
    }

    fn handle_notify(
        &mut self,
        _space: Arc<KitsuneSpace>,
        _to_agent: Arc<KitsuneAgent>,
        _from_agent: Arc<KitsuneAgent>,
        _payload: Vec<u8>,
    ) -> event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
    }

    fn handle_gossip(
        &mut self,
        _space: Arc<KitsuneSpace>,
        _to_agent: Arc<KitsuneAgent>,
        _from_agent: Arc<KitsuneAgent>,
        _op_hash: Arc<KitsuneOpHash>,
        _op_data: Vec<u8>,
    ) -> event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
    }

    fn handle_fetch_op_hashes_for_constraints(
        &mut self,
        _input: event::FetchOpHashesForConstraintsEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<Arc<KitsuneOpHash>>> {
        unimplemented!()
    }

    fn handle_fetch_op_hash_data(
        &mut self,
        _input: event::FetchOpHashDataEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<(Arc<KitsuneOpHash>, Vec<u8>)>> {
        unimplemented!()
    }

    fn handle_sign_network_data(
        &mut self,
        input: event::SignNetworkDataEvt,
    ) -> event::KitsuneP2pEventHandlerResult<KitsuneSignature> {
        let event::SignNetworkDataEvt {
            space: _,
            agent,
            data,
        } = input;
        let agent: KdHash = agent.into();
        let data = sodoken::Buffer::from_ref(&*data);
        let fut = self.handle_sign(agent, data)?;
        Ok(async move {
            let sig = fut.await?;
            Ok(KitsuneSignature(sig.to_vec()))
        }
        .boxed()
        .into())
    }
}

impl ghost_actor::GhostHandler<KdApi> for KdActor {}

impl KdApiHandler for KdActor {
    fn handle_list_transport_bindings(&mut self) -> KdApiHandlerResult<Vec<Url2>> {
        let fut = self.binding.list_transport_bindings();
        Ok(async move { Ok(fut.await?) }.boxed().into())
    }

    fn handle_generate_agent(&mut self) -> KdApiHandlerResult<KdHash> {
        Ok(self.keystore.generate_sign_agent())
    }

    fn handle_sign(
        &mut self,
        pub_key: KdHash,
        data: sodoken::Buffer,
    ) -> KdApiHandlerResult<Arc<[u8; 64]>> {
        Ok(self.keystore.sign(pub_key, data))
    }

    fn handle_join(&mut self, root_agent: KdHash, acting_agent: KdHash) -> KdApiHandlerResult<()> {
        let fut = self.binding.join(root_agent.into(), acting_agent.into());

        Ok(async move { Ok(fut.await?) }.boxed().into())
    }

    fn handle_activate(
        &mut self,
        acting_agent: KdHash,
    ) -> KdApiHandlerResult<tokio::sync::mpsc::Receiver<KdEvent>> {
        let (send, recv) = tokio::sync::mpsc::channel(10);
        self.active.insert(acting_agent, send);
        Ok(async move { Ok(recv) }.boxed().into())
    }

    fn handle_message(
        &mut self,
        root_agent: KdHash,
        from_active_agent: KdHash,
        to_active_agent: KdHash,
        content: serde_json::Value,
    ) -> KdApiHandlerResult<()> {
        let msg = Wire::Message(Message { content })
            .encode_vec()
            .map_err(KdError::other)?;

        let fut = self.binding.rpc_single(
            root_agent.into(),
            to_active_agent.into(),
            from_active_agent.into(),
            msg,
            None,
        );

        Ok(async move {
            let _res = fut.await?;
            Ok(())
        }
        .boxed()
        .into())
    }
}
