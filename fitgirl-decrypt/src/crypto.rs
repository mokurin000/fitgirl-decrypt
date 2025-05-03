use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

use crate::{types::CompressionType, Error};

pub fn decrypt_aes_256_gcm(
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
