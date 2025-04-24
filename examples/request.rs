use std::{error::Error, fs};

use base64::{prelude::BASE64_STANDARD, Engine};
use fitgirl_decrypt::Paste;

fn main() -> Result<(), Box<dyn Error>> {
    let paste = Paste::parse_url("https://paste.fitgirl-repacks.site/?225484ced69df1d1#SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW")?;

    let torrent_uri = paste.decrypt()?.attachment;
    let base64_content = torrent_uri.split_once(",").unwrap().1;

    let torrent = BASE64_STANDARD.decode(base64_content)?;
    fs::write("test.torrent", torrent)?;

    Ok(())
}
