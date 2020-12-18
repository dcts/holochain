use crate::*;

mod persist;
use persist::*;

mod keystore;
pub use keystore::KdHash;
use keystore::*;

pub(crate) struct KdActor {
    channel_factory: ghost_actor::actor_builder::GhostActorChannelFactory<Self>,
    i_s: ghost_actor::GhostSender<Internal>,
    keystore: KeystoreSender,
}

impl ghost_actor::GhostControlHandler for KdActor {}

impl KdActor {
    pub async fn new(
        channel_factory: ghost_actor::actor_builder::GhostActorChannelFactory<Self>,
    ) -> KdResult<Self> {
        let i_s = channel_factory.create_channel::<Internal>().await?;
        let persist = spawn_persist().await?;
        let keystore = spawn_keystore(persist).await?;
        Ok(KdActor {
            channel_factory,
            i_s,
            keystore,
        })
    }
}

ghost_actor::ghost_chan! {
    chan Internal<KdError> {
        fn attach_kitsune(
            bound_urls: Vec<Url2>,
            p2p: ghost_actor::GhostSender<actor::KitsuneP2p>,
            evt: futures::channel::mpsc::Receiver<event::KitsuneP2pEvent>,
        ) -> ();
    }
}

impl ghost_actor::GhostHandler<Internal> for KdActor {}

impl InternalHandler for KdActor {
    fn handle_attach_kitsune(
        &mut self,
        bound_urls: Vec<Url2>,
        _p2p: ghost_actor::GhostSender<actor::KitsuneP2p>,
        evt: futures::channel::mpsc::Receiver<event::KitsuneP2pEvent>,
    ) -> InternalHandlerResult<()> {
        println!("BOUND_URL: {:#?}", bound_urls);
        let attach_fut = self.channel_factory.attach_receiver(evt);
        Ok(async move {
            attach_fut.await?;
            Ok(())
        }
        .boxed()
        .into())
    }
}

impl ghost_actor::GhostHandler<event::KitsuneP2pEvent> for KdActor {}

impl event::KitsuneP2pEventHandler for KdActor {
    fn handle_put_agent_info_signed(
        &mut self,
        _input: event::PutAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
    }

    fn handle_get_agent_info_signed(
        &mut self,
        _input: event::GetAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Option<agent_store::AgentInfoSigned>> {
        unimplemented!()
    }

    fn handle_query_agent_info_signed(
        &mut self,
        _input: event::QueryAgentInfoSignedEvt,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<agent_store::AgentInfoSigned>> {
        unimplemented!()
    }

    fn handle_call(
        &mut self,
        _space: Arc<KitsuneSpace>,
        _to_agent: Arc<KitsuneAgent>,
        _from_agent: Arc<KitsuneAgent>,
        _payload: Vec<u8>,
    ) -> event::KitsuneP2pEventHandlerResult<Vec<u8>> {
        unimplemented!()
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
        _input: event::SignNetworkDataEvt,
    ) -> event::KitsuneP2pEventHandlerResult<KitsuneSignature> {
        unimplemented!()
    }
}

impl ghost_actor::GhostHandler<KdApi> for KdActor {}

impl KdApiHandler for KdActor {
    fn handle_create_kitsune(&mut self, _config_directives: Vec<String>) -> KdApiHandlerResult<()> {
        let i_s = self.i_s.clone();
        Ok(async move {
            let mut config = KitsuneP2pConfig::default();

            config.transport_pool.push(TransportConfig::Proxy {
                sub_transport: Box::new(TransportConfig::Mem {}),
                proxy_config: ProxyConfig::LocalProxyServer {
                    proxy_accept_config: Some(ProxyAcceptConfig::RejectAll),
                },
            });

            let (p2p, evt) = spawn_kitsune_p2p(
                config,
                kitsune_p2p_proxy::TlsConfig::new_ephemeral().await.unwrap(),
            )
            .await?;

            let bound_urls = p2p.list_transport_bindings().await?;

            i_s.attach_kitsune(bound_urls, p2p, evt).await?;

            Ok(())
        }
        .boxed()
        .into())
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
}
