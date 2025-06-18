#[cfg(any(feature = "reqwest", feature = "nyquest"))]
use fitgirl_decrypt::{Error, Paste};

#[cfg(feature = "reqwest")]
#[tokio::test]
async fn test_reqwest_decrypt() -> Result<(), Error> {
    let url = "https://paste.fitgirl-repacks.site/?e9a29aba6419df2e#EPGKu25RdaUZu45s4yrmpDLKVmFZq214VCos2t9M54a7";
    let paste = Paste::parse_url(url)?;

    let cipher_info = paste.request_async().await?;
    paste.decrypt(cipher_info)?;

    Ok(())
}

#[cfg(feature = "nyquest")]
#[tokio::test]
async fn test_nyquest_decrypt() -> Result<(), Error> {
    let _ = init_nyquest();
    let url = "https://paste.fitgirl-repacks.site/?e9a29aba6419df2e#EPGKu25RdaUZu45s4yrmpDLKVmFZq214VCos2t9M54a7";
    let paste = Paste::parse_url(url)?;

    let cipher_info = paste.request_async_ny().await?;

    let masterkey = paste.master_key().to_owned();
    tokio::task::spawn_blocking(|| {
        use fitgirl_decrypt::decrypt_with_key;

        decrypt_with_key(masterkey, cipher_info)
    })
    .await
    .expect("join error")?;

    Ok(())
}

#[rstest::fixture]
fn init_nyquest() {
    nyquest_preset::register();
}
