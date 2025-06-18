use std::num::NonZero;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;

use crate::{types::CompressionType, Error};
use crate::{Attachment, Cipher, CipherInfo};

/// Decrypt paste using given master_key
pub fn decrypt_with_key(
    master_key: impl AsRef<[u8]>,
    cipher: impl AsRef<CipherInfo>,
) -> crate::Result<Attachment> {
    let CipherInfo { adata, ct } = cipher.as_ref();

    let Cipher {
        cipher_iv,
        kdf_salt,
        kdf_iterations,
        compression_type,
        ..
    } = &adata.cipher;

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
        master_key.as_ref(),
        &mut derived_key,
    );

    let adata_json = serde_json::to_string(&adata)?;

    let data = decrypt_aes_256_gcm(&ct, &derived_key, cipher_iv, &adata_json, compression_type)?;
    Ok(serde_json::from_slice(&data)?)
}

fn decrypt_aes_256_gcm(
    ct: &[u8],
    derived_key: &[u8; 32],
    iv: Vec<u8>,
    adata_json: &str,
    compression_type: &CompressionType,
) -> crate::Result<Vec<u8>> {
    type Cipher = aes_gcm::AesGcm<aes_gcm::aes::Aes256, typenum::U16>;

    let cipher = Cipher::new(Key::<Aes256Gcm>::from_slice(derived_key));
    let payload = aes_gcm::aead::Payload {
        msg: ct,
        aad: adata_json.as_bytes(),
    };
    let data = cipher
        .decrypt(Nonce::from_slice(&iv), payload)
        .map_err(|_| Error::AesGcm)?;

    let decompressed = match compression_type {
        CompressionType::None => data,
        CompressionType::Zlib => {
            miniz_oxide::inflate::decompress_to_vec(&data).map_err(|_| Error::DecompressError)?
        }
    };

    Ok(decompressed)
}
