use serde::{ser::SerializeTuple as _, Deserialize, Serialize, Serializer};

/// CipherInfo is directly from the JSON returned from privatebin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    /// additional data about a paste
    pub adata: AData,
    /// cipher text, in base64
    pub ct: String,
}

/// Additional data about a paste.
#[derive(Debug, Clone, Deserialize)]
pub struct AData {
    /// everything related to decrypt cipher text
    pub cipher: Cipher,
    /// post formatter, can be "plaintext" or "markdown"
    pub formatter: String,
    /// accepts comments
    pub open_discussion: u8,
    /// will burn after one access
    pub burn_after_reading: u8,
}

impl AsRef<CipherInfo> for CipherInfo {
    fn as_ref(&self) -> &CipherInfo {
        &self
    }
}

/// [`Cipher`] contains AES-GCM related fields,
/// which is an array in original JSON.
///
/// [`serde`] could deserialize this from an 8 length list.
#[derive(Deserialize, Debug, Clone)]
pub struct Cipher {
    /// IV (nonce), in base64
    pub cipher_iv: String,
    /// pbkdf2 salt, in base64
    pub kdf_salt: String,
    /// pbkdf2 iterations
    pub kdf_iterations: u32,
    /// pbkdf2 generated key size, always 256 (bits)
    pub kdf_keysize: u32,
    /// tag size in GCM, always 128 (bits)
    pub cipher_tag_size: u32,
    /// encryption algorithm, always `"aes"`
    pub cipher_algo: String,
    /// aes encryption mode, always `"gcm"`
    pub cipher_mode: String,
    /// compression type of encrypted data. either "zlib" or "none"
    pub compression_type: CompressionType,
}

/// Compression type
#[derive(Default, Deserialize, Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CompressionType {
    /// no compression
    None,
    /// zlib (flate) compression
    #[default]
    Zlib,
}

impl Serialize for AData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_tuple(4)?;
        s.serialize_element(&self.cipher)?;
        s.serialize_element(&self.formatter)?;
        s.serialize_element(&self.open_discussion)?;
        s.serialize_element(&self.burn_after_reading)?;
        s.end()
    }
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
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// data URI startswith `data:application/x-bittorrent;base64,`
    pub attachment: String,
    /// suggested filename of the attachment
    pub attachment_name: String,
}
