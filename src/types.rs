use serde::{ser::SerializeTuple as _, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    pub adata: (Cipher, String, u8, u8),
    pub ct: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Cipher {
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
pub enum CompressionType {
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub attachment: String,
    pub attachment_name: String,
}
