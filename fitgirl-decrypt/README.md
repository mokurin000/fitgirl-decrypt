# fitgirl-decrypt

Decrypt torrents from Fitgirl-Repacks PrivateBin services.

It's possibly general, but expect bugs. PBKDF2 key length (32 bytes), AES mode (GCM), GCM tag size (16 bytes), are hard-coded.

## Features

fitgirl-decrypt supports various http request backends, including:

[`ureq`]: https://docs.rs/ureq/latest/ureq/index.html
[`reqwest`]: https://docs.rs/reqwest/latest/reqwest/index.html
[`nyquest`]: https://docs.rs/nyquest/latest/nyquest/index.html

| Backend     | Binary size* | async? | Comment    |
| ----------- | ------------ | ------ | ---------- |
| None        | 136.1 kB     | -      |            |
| [`ureq`]    | 2.0 MB       | no     |            |
| [`nyquest`] | 460.8 kB     | yes    | with tokio |
| [`reqwest`] | 2.3 MB       | yes    | with tokio |

*: Compiled on `x86_64-pc-windows-msvc` with patched release profile, with tokio

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
