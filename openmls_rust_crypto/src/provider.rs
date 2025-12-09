use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use hpke::Hpke;
use hpke_rs_crypto::types as hpke_types;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, Ciphersuite, CryptoError, ExporterSecret,
        HpkeCiphertext, HpkeConfig, HpkeKeyPair,
    },
};
use p256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

use crate::hmac;

#[derive(Debug)]
pub struct RustCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

// For testing we want to clone.
// But really we just create a new Rng.
#[cfg(feature = "test-utils")]
impl Clone for RustCrypto {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

#[inline(always)]
fn kem_mode(ciphersuite: Ciphersuite) -> hpke_types::KemAlgorithm {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke_types::KemAlgorithm::DhKem25519
        }
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke_types::KemAlgorithm::DhKemP256,
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => hpke_types::KemAlgorithm::DhKem448,
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => hpke_types::KemAlgorithm::DhKemP384,
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => hpke_types::KemAlgorithm::DhKemP521,
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            unimplemented!("XWingKemDraft6 is not supported by the RustCrypto provider.")
        }
        Ciphersuite::Custom(_) => {
            unimplemented!("Custom ciphersuites are not supported by the RustCrypto provider.")
        }
    }
}

#[inline(always)]
fn kdf_mode(ciphersuite: Ciphersuite) -> hpke_types::KdfAlgorithm {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke_types::KdfAlgorithm::HkdfSha256
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => hpke_types::KdfAlgorithm::HkdfSha384,
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hpke_types::KdfAlgorithm::HkdfSha512
        }
        Ciphersuite::Custom(_) => {
            unimplemented!("Custom ciphersuites are not supported by the RustCrypto provider.")
        }
    }
}

#[inline(always)]
fn aead_mode(ciphersuite: Ciphersuite) -> hpke_types::AeadAlgorithm {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke_types::AeadAlgorithm::Aes128Gcm,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke_types::AeadAlgorithm::ChaCha20Poly1305
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => hpke_types::AeadAlgorithm::Aes256Gcm,
        Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hpke_types::AeadAlgorithm::ChaCha20Poly1305
        }
        Ciphersuite::Custom(_) => {
            unimplemented!("Custom ciphersuites are not supported by the RustCrypto provider.")
        }
    }
}

impl OpenMlsCrypto for RustCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    fn hkdf_extract(
        &self,
        ciphersuite: Ciphersuite,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        #[allow(deprecated)]
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into())
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into())
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into())
            }
            Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn hmac(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        hmac::hmac(ciphersuite, key, message)
    }

    fn hkdf_expand(
        &self,
        ciphersuite: Ciphersuite,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn hash(
        &self,
        ciphersuite: Ciphersuite,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        #[allow(deprecated)]
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                Ok(Sha256::digest(data).as_slice().into())
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Ok(Sha384::digest(data).as_slice().into())
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                Ok(Sha512::digest(data).as_slice().into())
            }
            Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn aead_encrypt(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn aead_decrypt(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn signature_key_gen(
        &self,
        ciphersuite: Ciphersuite,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let k = SigningKey::random(&mut *rng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                #[allow(deprecated)]
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let sk = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = sk.verifying_key().to_bytes().into();
                Ok((sk.to_bytes().into(), pk))
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn verify_signature(
        &self,
        ciphersuite: Ciphersuite,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let k = VerifyingKey::from_encoded_point(
                    &EncodedPoint::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?,
                )
                .map_err(|_| CryptoError::CryptoLibraryError)?;
                k.verify(
                    data,
                    &Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?,
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let k = ed25519_dalek::VerifyingKey::try_from(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::CryptoLibraryError);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::from(sig))
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn sign(
        &self,
        ciphersuite: Ciphersuite,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let k = SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: Signature = k.sign(data);
                Ok(signature.to_der().to_bytes().into())
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                let k = ed25519_dalek::SigningKey::try_from(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_bytes().into())
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let (kem_output, ciphertext) = hpke_from_config(config)
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_from_config(config)
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let (kem_output, context) = hpke_from_config(config)
            .setup_sender(&pk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, exported_secret.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let context = hpke_from_config(config)
            .setup_receiver(enc, &sk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok(exported_secret.into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<types::HpkeKeyPair, CryptoError> {
        let kp = hpke_from_config(config)
            .derive_key_pair(ikm)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?
            .into_keys();
        Ok(HpkeKeyPair {
            private: kp.0.as_slice().into(),
            public: kp.1.as_slice().into(),
        })
    }
}

fn hpke_from_config(config: HpkeConfig) -> Hpke<HpkeRustCrypto> {
    let ciphersuite = config.0;
    Hpke::<HpkeRustCrypto>::new(
        hpke::Mode::Base,
        kem_mode(ciphersuite),
        kdf_mode(ciphersuite),
        aead_mode(ciphersuite),
    )
}

impl OpenMlsRand for RustCrypto {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RandError {
    #[error("Rng lock is poisoned.")]
    LockPoisoned,
    #[error("Unable to collect enough randomness.")]
    NotEnoughRandomness,
}
