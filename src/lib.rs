use std::num::NonZero;

use base64::{prelude::BASE64_STANDARD, Engine};
use crypto::decrypt_aes_256_gcm;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Paste<'a> {
    key: Vec<u8>,
    key_base58: &'a str,
    pasteid: &'a str,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key length not match! expected 32, got {0}")]
    KeyLengthMismatch(usize),
    #[error("iterations must be non zero!")]
    ZeroIterations,

    #[error("request error: {0}")]
    Ureq(#[from] ureq::Error),

    #[error("base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("zlib decompress error")]
    DecompressError,

    #[error("aes-256-gcm decryption error")]
    AesGcm,

    #[error("serialize error: {0}")]
    JSONSerialize(#[from] serde_json::Error),
}

impl Paste<'_> {
    pub fn try_from_key_and_pasteid<'a>(
        key_base58: &'a str,
        pasteid: &'a str,
    ) -> Result<Paste<'a>> {
        let key = bs58::decode(key_base58).into_vec()?;

        if key.len() != 32 {
            return Err(Error::KeyLengthMismatch(key.len()));
        }

        Ok(Paste {
            key,
            key_base58,
            pasteid,
        })
    }

    pub fn decrypt(&self) -> Result<Attachment> {
        let CipherInfo { adata, ct } = self.request()?;

        let Cipher {
            cipher_iv,
            kdf_salt,
            kdf_iterations,
            compression_type,
            ..
        } = &adata.0;

        let master_key = &self.key;
        let ct = BASE64_STANDARD.decode(ct)?;
        let cipher_iv = BASE64_STANDARD.decode(cipher_iv)?;
        let kdf_salt = BASE64_STANDARD.decode(kdf_salt)?;
        let iterations = NonZero::new(*kdf_iterations).ok_or(Error::ZeroIterations)?;
        let algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;

        let mut derived_key = [0u8; 32];
        ring::pbkdf2::derive(
            algorithm,
            iterations,
            &kdf_salt,
            master_key,
            &mut derived_key,
        );

        let adata_json = serde_json::to_string(&adata)?;

        let data =
            decrypt_aes_256_gcm(&ct, &derived_key, cipher_iv, &adata_json, compression_type)?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn request(&self) -> Result<CipherInfo> {
        use ureq::{http::header::ACCEPT, Agent};

        let pasteid = self.pasteid;
        let key_base58 = self.key_base58;

        let init_cookies = format!("https://paste.fitgirl-repacks.site/?{pasteid}#{key_base58}");
        let cipher_info = format!("https://paste.fitgirl-repacks.site/?pasteid={pasteid}");

        let agent = Agent::new_with_defaults();

        agent.get(init_cookies).call()?;

        let resp = agent
            .get(cipher_info)
            .header(ACCEPT, "application/json")
            .call()?
            .body_mut()
            .read_json()?;

        Ok(resp)
    }
}

mod types;
use types::{Attachment, Cipher, CipherInfo};

mod crypto;
