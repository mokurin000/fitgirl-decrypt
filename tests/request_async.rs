use fitgirl_decrypt::{Error, Paste};

#[tokio::test]
async fn test_decrypt() -> Result<(), Error> {
    let url = "https://paste.fitgirl-repacks.site/?e9a29aba6419df2e#EPGKu25RdaUZu45s4yrmpDLKVmFZq214VCos2t9M54a7";
    let paste = Paste::parse_url(url)?;

    let cipher_info = paste.request_async().await?;
    paste.decrypt(cipher_info)?;

    Ok(())
}
