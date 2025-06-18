#![doc = include_str!("../../README.md")]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]

mod types;
pub use types::{Attachment, Cipher, CipherInfo, CompressionType};

mod crypto;
pub use crypto::decrypt_with_key;

mod error;
pub use error::Error;

/// [`Paste`] stores pasteid and key.
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Paste<'a> {
    key: Vec<u8>,
    key_base58: &'a str,
    pasteid: &'a str,
    base_url: &'a str,
}

/// Alias of Result with [`Error`] as E.
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
        let (base_url, pasteinfo) = url.split_once('?').ok_or(Error::IllFormedURL)?;
        let (pasteid, key_base58) = pasteinfo.split_once("#").ok_or(Error::IllFormedURL)?;

        let paste = Self::try_from_key_and_pasteid(key_base58, pasteid)?;
        Ok(Paste { base_url, ..paste })
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

        let base_url = "https://paste.fitgirl-repacks.site/";

        Ok(Paste {
            key,
            key_base58,
            pasteid,
            base_url,
        })
    }

    /// Decrypt paste from [`CipherInfo`].
    pub fn decrypt(&self, cipher: impl AsRef<CipherInfo>) -> Result<Attachment> {
        decrypt_with_key(&self.master_key(), cipher.as_ref())
    }

    pub fn master_key(&self) -> &Vec<u8> {
        &self.key
    }

    /// Get [`CipherInfo`] to decrypt synchronously, with [`ureq`].
    #[cfg_attr(feature = "nightly", doc(cfg(feature = "ureq")))]
    #[cfg(feature = "ureq")]
    pub fn request(&self) -> Result<CipherInfo> {
        use ureq::{http::header::ACCEPT, Agent};

        let pasteid = self.pasteid;
        let key_base58 = self.key_base58;

        let base = self.base_url;
        let init_cookies = format!("{base}?{pasteid}#{key_base58}");
        let cipher_info = format!("{base}?pasteid={pasteid}");

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

    /// Get [`CipherInfo`] to decrypt asynchronously, with [`reqwest`].
    ///
    /// ## NOTE
    ///
    /// Because reqwest depends on tokio types, if you are using an async runtime
    ///
    /// other than tauri and tokio, try to spawn this inside tokio context.
    ///
    /// Also see [async_compat](https://docs.rs/async-compat/latest/async_compat/)
    #[cfg_attr(feature = "nightly", doc(cfg(feature = "reqwest")))]
    #[cfg(feature = "reqwest")]
    pub async fn request_async(&self) -> Result<CipherInfo> {
        use reqwest::{header::ACCEPT, ClientBuilder};

        let pasteid = self.pasteid;
        let key_base58 = self.key_base58;

        let base = self.base_url;
        let init_cookies = format!("{base}?{pasteid}#{key_base58}");
        let cipher_info = format!("{base}?pasteid={pasteid}");

        let client = ClientBuilder::new().gzip(true).build()?;
        client.get(init_cookies).send().await?;

        let resp = client
            .get(cipher_info)
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    /// Get [`CipherInfo`] to decrypt asynchronously, with [`nyquest`].
    ///
    /// Nyquest can be much more lightweight than [`reqwest`], though it's experimental.
    #[cfg_attr(feature = "nightly", doc(cfg(feature = "nyquest")))]
    #[cfg(feature = "nyquest")]
    pub async fn request_async_ny(&self) -> Result<CipherInfo> {
        use nyquest::{r#async::Request, ClientBuilder};

        let pasteid = self.pasteid;
        let key_base58 = self.key_base58;

        let base = self.base_url;
        let init_cookies = format!("/?{pasteid}#{key_base58}");
        let cipher_info = format!("/?pasteid={pasteid}");

        let client = ClientBuilder::default()
            .base_url(base)
            .build_async()
            .await?;
        client.request(Request::get(init_cookies)).await?;

        let resp = client
            .request(Request::get(cipher_info).with_header("Accept", "application/json"))
            .await?
            .json()
            .await?;
        Ok(resp)
    }
}

/// re-export of base64 for torrent decoding.
pub use base64;
