use serde::{ser::SerializeTuple as _, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CipherInfo {
    pub adata: (Cipher, String, u8, u8),
    pub ct: String,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Cipher {
    pub cipher_iv: String,
    pub kdf_salt: String,
    pub kdf_iterations: u32,
    pub kdf_keysize: u32,
    pub cipher_tag_size: u32,
    pub cipher_algo: String,
    pub cipher_mode: String,
    pub compression_type: CompressionType,
}

#[derive(Default, Deserialize, Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CompressionType {
    None,
    #[default]
    Zlib,
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_tuple(8)?;
        s.serialize_element(&self.cipher_iv)?;
        s.serialize_element(&self.kdf_salt)?;
        s.serialize_element(&self.kdf_iterations)?;
        s.serialize_element(&self.kdf_keysize)?;
        s.serialize_element(&self.cipher_tag_size)?;
        s.serialize_element(&self.cipher_algo)?;
        s.serialize_element(&self.cipher_mode)?;
        s.serialize_element(&self.compression_type)?;
        s.end()
    }
}

/// `Attachment` is from the decrypted paste JSON.
///
/// ```rust
/// use fitgirl_decrypt::base64::{prelude::BASE64_STANDARD, Engine};
/// use fitgirl_decrypt::{Paste, Attachment};
///
/// let paste = Paste::parse_url("https://paste.fitgirl-repacks.site/?225484ced69df1d1#SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW")
///     .expect("parse error");
/// let Attachment { attachment, .. } = paste.decrypt()
///     .expect("failed to decrypt");
///
/// let base64 = attachment.strip_prefix("data:application/x-bittorrent;base64,").unwrap();
/// let torrent = BASE64_STANDARD.decode(base64).expect("decode failed");
///
/// let paste = Paste::parse_url("https://pastefg.hermietkreeft.site/?504bf00f08cb6c26#Cg1BP1oPRYGGffdNyrNUca9AUpstsHRz7McPnEaUUTLo")
///     .expect("parse error");
/// let Attachment { attachment, .. } = paste.decrypt()
///     .expect("failed to decrypt");
///
/// let base64 = attachment.strip_prefix("data:application/x-bittorrent;base64,").unwrap();
/// let torrent = BASE64_STANDARD.decode(base64).expect("decode failed");
/// ```
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// data URI startswith `data:application/x-bittorrent;base64,`
    pub attachment: String,
    /// suggested filename of the attachment
    pub attachment_name: String,
}
