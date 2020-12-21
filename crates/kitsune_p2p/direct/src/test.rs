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
    })
    .await?;

    kd.create_kitsune(vec![
        "set_proxy_accept_all:".to_string(),
        "bind_mem_local:".to_string(),
    ]).await?;

    let url1 = kd.list_connection_urls().await?[0].clone();
    println!("got connection: {:?}", url1);

    let agent1 = kd.generate_agent().await?;
    println!("got agent: {}", agent1);

    Ok(())
}
