use std::{error::Error, fs};

use base64::{prelude::BASE64_STANDARD, Engine};
use fitgirl_decrypt::Paste;

fn main() -> Result<(), Box<dyn Error>> {
    let key_base58 = "SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW";
    let pasteid = "225484ced69df1d1";
    let paste = Paste::try_from_key_and_pasteid(key_base58, pasteid)?;

    let torrent_uri = paste.decrypt()?.attachment;
    let base64_content = torrent_uri.split_once(",").unwrap().1;

    let torrent = BASE64_STANDARD.decode(base64_content)?;
    fs::write("test.torrent", torrent)?;

    Ok(())
}
