use serde::Serialize;
use thiserror::Error;

/// Possible errors during requesting/decrypting/decoding/deserialization e.g.
#[derive(Debug, Error)]
pub enum Error {
    #[error("key length not match! expected 32, got {0}")]
    KeyLengthMismatch(usize),
    #[error("iterations must be non zero!")]
    ZeroIterations,
    #[error("url must be like https://paste.fitgirl-repacks.site/?{{pasteid}}#{{key_base58}}")]
    IllFormedURL,

    #[cfg(feature = "ureq")]
    #[error("request error: {0}")]
    Ureq(#[from] ureq::Error),
    #[cfg(feature = "reqwest")]
    #[error("request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[cfg(feature = "nyquest")]
    #[error("request error: {0}")]
    Nyquest(#[from] nyquest::Error),
    #[cfg(feature = "nyquest")]
    #[error("build client error: {0}")]
    NyquestBuildClient(#[from] nyquest::client::BuildClientError),

    #[error("base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("zlib decompress error")]
    DecompressError,

    #[error("aes-256-gcm decryption error")]
    AesGcm,

    #[error("deserialize error: {0}")]
    JSONSerialize(#[from] serde_json::Error),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
