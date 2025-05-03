# fitgirl-decrypt

Decrypt torrents from Fitgirl-Repacks PrivateBin services.

It's possibly general, but expect bugs. PBKDF2 key length (32 bytes), AES mode (GCM), GCM tag size (16 bytes), are hard-coded.

## Examples

```rust
use fitgirl_decrypt::base64::prelude::*;
use fitgirl_decrypt::{Paste, Attachment};

#[cfg(feature = "ureq")]
fn decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://paste.fitgirl-repacks.site/?e9a29aba6419df2e#EPGKu25RdaUZu45s4yrmpDLKVmFZq214VCos2t9M54a7";
    let paste = Paste::parse_url(url)?;
    let cipher_info = paste.request()?;
    let Attachment { attachment, .. } = paste.decrypt(&cipher_info)
        .expect("failed to decrypt");

    let base64 = attachment.strip_prefix("data:application/x-bittorrent;base64,").unwrap();
    let torrent = BASE64_STANDARD.decode(base64).expect("decode failed");

    Ok(())
}

#[cfg(feature = "ureq")]
decrypt().unwrap()
```
