use hmac::Mac;
use openmls_traits::types;
use openmls_traits::types::{Ciphersuite, CryptoError};
use sha2::{Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

type HmacSha256 = hmac::Hmac<Sha256>;
type HmacSha384 = hmac::Hmac<Sha384>;
type HmacSha512 = hmac::Hmac<Sha512>;

macro_rules! hmac_digest {
    ($hash_t:ty, $key:ident, $message:ident) => {{
        let mut hmac = <$hash_t>::new_from_slice($key).map_err(|_e| CryptoError::InvalidLength)?;
        hmac.update($message);
        #[allow(deprecated)]
        hmac.finalize().into_bytes().as_slice().to_vec()
    }};
}

pub(crate) fn hmac(
    ciphersuite: Ciphersuite,
    key: &[u8],
    message: &[u8],
) -> Result<SecretVLBytes, types::CryptoError> {
    let digest: Vec<u8> = match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            hmac_digest!(HmacSha256, key, message)
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            hmac_digest!(HmacSha384, key, message)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hmac_digest!(HmacSha512, key, message)
        }
        Ciphersuite::Custom(_) => return Err(CryptoError::UnsupportedCiphersuite),
    };
    Ok(SecretVLBytes::new(digest))
}
