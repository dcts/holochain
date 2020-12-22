use crate::*;

#[tokio::test(threaded_scheduler)]
async fn sanity() {
    if let Err(e) = sanity_inner().await {
        panic!("{:#?}", e);
    }
}

async fn sanity_inner() -> KdResult<()> {
    let kd = spawn_kitsune_p2p_direct(KdConfig {
        persist_path: None,
        unlock_passphrase: sodoken::Buffer::new_memlocked(4)?,
        directives: vec![
            "set_proxy_accept_all:".to_string(),
            "bind_mem_local:".to_string(),
        ],
    })
    .await?;

    let url1 = kd.list_transport_bindings().await?[0].clone();
    println!("got connection: {:?}", url1);

    let agent1 = kd.generate_agent().await?;
    println!("got agent: {}", agent1);

    kd.join(agent1.clone(), agent1.clone()).await?;

    let mut recv = kd.activate(agent1.clone()).await?;
    tokio::task::spawn(async move {
        use tokio::stream::StreamExt;
        while let Some(evt) = recv.next().await {
            println!("GOT: {:?}", evt);
        }
    });

    kd.message(
        agent1.clone(),
        agent1.clone(),
        agent1.clone(),
        serde_json::json! {{
            "test": "message",
            "age": 42
        }},
    )
    .await?;

    Ok(())
}
