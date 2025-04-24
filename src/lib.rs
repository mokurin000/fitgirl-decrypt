use std::num::NonZero;

use base64::{prelude::BASE64_STANDARD, Engine};

mod types;
pub use types::Attachment;
use types::{Cipher, CipherInfo};

mod crypto;
use crypto::decrypt_aes_256_gcm;

mod error;
pub use error::Error;

/// [`Paste`] stores pasteid and key.
#[derive(Debug, Clone)]
pub struct Paste<'a> {
    key: Vec<u8>,
    key_base58: &'a str,
    pasteid: &'a str,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Paste<'_> {
    /// Parse paste info from an URL.
    ///
    /// ```rust
    /// use fitgirl_decrypt::{Paste, Error};
    ///
    /// let url1 = "https://paste.fitgirl-repacks.site/?225484ced69df1d1#SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW";
    /// let url2 = "https://paste.fitgirl-repacks.site/?225484ced69df1d1#kWYCcn3qmpehWMMBmZ1NJciKNA6eXfK6LPzwgGXFdJ";
    ///
    /// assert!(Paste::parse_url(url1).is_ok());
    /// assert!(matches!(Paste::parse_url(url2), Err(Error::KeyLengthMismatch(31))));
    /// ```
    pub fn parse_url<'a>(url: &'a str) -> Result<Paste<'a>> {
        let (pasteid, key_base58) = url
            .split_once('?')
            .ok_or(Error::IllFormedURL)?
            .1
            .split_once("#")
            .ok_or(Error::IllFormedURL)?;

        Self::try_from_key_and_pasteid(key_base58, pasteid)
    }

    /// Parse paste info from key_base58 (the url segment after '#') and pasteid.
    ///
    /// ```rust
    /// use fitgirl_decrypt::{Paste, Error};
    ///
    /// assert!(
    ///     Paste::try_from_key_and_pasteid(
    ///         "SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW",
    ///         "",
    ///     )
    ///     .is_ok()
    /// );
    /// assert!(
    ///     matches!(
    ///         Paste::try_from_key_and_pasteid(
    ///             "kWYCcn3qmpehWMMBmZ1NJciKNA6eXfK6LPzwgGXFdJ",
    ///             "225484ced69df1d1",
    ///         ),
    ///         Err(Error::KeyLengthMismatch(31)),
    ///     )
    /// );
    /// ```
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

    /// Download the paste, and decrypt it's attachment.
    ///
    /// See [examples/request.rs](https://github.com/mokurin000/fitgirl-decrypt/blob/master/examples/request.rs) for more details.
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

pub use base64;
