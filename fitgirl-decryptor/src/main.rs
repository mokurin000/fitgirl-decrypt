use std::{error::Error, path::PathBuf};

use fitgirl_decrypt::{Attachment, Paste, base64::prelude::*};

#[derive(argh::FromArgs)]
#[argh(
    description = "decrypt & download attachment from some privatebin",
    help_triggers("-h", "--help", "help")
)]
struct Args {
    /// URL of the pastebin
    #[argh(option)]
    url: String,
    /// save to this directory
    #[argh(option, default = "PathBuf::from(\".\")")]
    output_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let Args { url, output_dir } = argh::from_env();

    let paste = Paste::parse_url(&url)?;
    let cipher_info = pollster::block_on(paste.request_async_ny())?;
    let Attachment {
        attachment,
        attachment_name,
    } = paste.decrypt(cipher_info)?;

    let torrent_b64 = attachment
        .strip_prefix("data:application/x-bittorrent;base64,")
        .ok_or_else(|| String::from("invalid data URI was returned!"))?;
    let torrent = BASE64_STANDARD.decode(torrent_b64)?;

    std::fs::create_dir_all(&output_dir)?;
    let save_path = output_dir.join(attachment_name);
    std::fs::write(save_path, torrent)?;

    Ok(())
}
