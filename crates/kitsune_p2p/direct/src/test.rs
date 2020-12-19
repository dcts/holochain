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
    kd.create_kitsune(vec![]).await?;

    Ok(())
}
