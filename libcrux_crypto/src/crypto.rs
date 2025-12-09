use hpke_rs_libcrux::HpkeLibcrux;

use std::sync::{Mutex, MutexGuard};

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    Ciphersuite, CryptoError, ExporterSecret, HpkeCiphertext, HpkeKeyPair, KemOutput,
    SignatureScheme,
};

use rand::{rngs::OsRng, rngs::ReseedingRng, CryptoRng, RngCore};
use rand_chacha::ChaCha20Core;

use tls_codec::SecretVLBytes;

/// The libcrux-backed cryptography provider for OpenMLS
pub struct CryptoProvider {
    pub(super) rng: Mutex<ReseedingRng<ChaCha20Core, OsRng>>,
}

impl CryptoProvider {
    /// Instantiate a libcrux-based CryptoProvider
    pub fn new() -> Result<Self, CryptoError> {
        let reseeding_rng = ReseedingRng::<ChaCha20Core, _>::new(0x100000000, OsRng)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(Self {
            rng: Mutex::new(reseeding_rng),
        })
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            // TODO: enable
            //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    fn hkdf_extract(
        &self,
        ciphersuite: Ciphersuite,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(ciphersuite)?;

        let mut prk = vec![0u8; alg.hash_len()];

        libcrux_hkdf::extract(alg, &mut prk, salt, ikm)
            .map_err(|e| match e {
                libcrux_hkdf::ExtractError::ArgumentTooLong => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })
            .map(|_| prk.into())
    }

    fn hmac(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hash_alg(ciphersuite)?;
        let out = libcrux_hmac::hmac(alg, key, message, None);
        Ok(out.into())
    }

    fn hkdf_expand(
        &self,
        ciphersuite: Ciphersuite,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(ciphersuite)?;

        let mut okm = vec![0u8; okm_len];

        libcrux_hkdf::expand(alg, &mut okm, prk, info)
            .map_err(|e| match e {
                libcrux_hkdf::ExpandError::OutputTooLong => CryptoError::HkdfOutputLengthInvalid,
                libcrux_hkdf::ExpandError::ArgumentTooLong => CryptoError::InvalidLength,
                // TODO: Potentially extend `CryptoError` with a variant for the `PrkTooShort` case
                libcrux_hkdf::ExpandError::PrkTooShort => CryptoError::InvalidLength,
                libcrux_hkdf::ExpandError::Unknown => CryptoError::CryptoLibraryError,
            })
            .map(|_| okm.into())
    }

    fn hash(&self, ciphersuite: Ciphersuite, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                libcrux_sha2::sha256(data).to_vec()
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                libcrux_sha2::sha384(data).to_vec()
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                libcrux_sha2::sha512(data).to_vec()
            }
            Ciphersuite::Custom(_) => return Err(CryptoError::UnsupportedCiphersuite),
        };

        Ok(out)
    }

    fn aead_encrypt(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_alg(ciphersuite)?;

        use libcrux_traits::aead::typed_refs::Aead as _;

        // set up buffers for ptxt, ctxt and tag
        let mut msg_ctxt: Vec<u8> = vec![0; data.len() + alg.tag_len()];
        let (msg, tag) = msg_ctxt.split_at_mut(data.len());

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg
            .new_tag_mut(tag)
            .map_err(|_| CryptoError::InvalidLength)?;

        key.encrypt(msg, tag, nonce, aad, data)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(msg_ctxt)
    }

    fn aead_decrypt(
        &self,
        ciphersuite: Ciphersuite,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_alg(ciphersuite)?;

        use libcrux_traits::aead::typed_refs::{Aead as _, DecryptError};

        if ct_tag.len() < alg.tag_len() {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - alg.tag_len();

        // set up buffers for ptext, ctext, and tag
        let mut ptext = vec![0; boundary];
        let (ctext, tag) = ct_tag.split_at(boundary);

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg.new_tag(tag).map_err(|_| CryptoError::InvalidLength)?;

        key.decrypt(&mut ptext, nonce, aad, ctext, tag)
            .map_err(|e| match e {
                DecryptError::InvalidTag => CryptoError::AeadDecryptionError,
                DecryptError::AadTooLong => CryptoError::InvalidLength,

                _ => CryptoError::CryptoLibraryError,
            })?;

        Ok(ptext)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let mut rng = self
            .rng
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(GuardedRng)?;

        libcrux_ed25519::generate_key_pair(&mut rng)
            .map_err(|_| CryptoError::SigningError)
            .map(|(signing_key, verification_key)| {
                (
                    signing_key.into_bytes().to_vec(),
                    verification_key.into_bytes().to_vec(),
                )
            })
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let pk = <&[u8; 32]>::try_from(pk).map_err(|_| CryptoError::InvalidLength)?;
        let sk = <&[u8; 64]>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;

        libcrux_ed25519::verify(data, pk, sk).map_err(|e| match e {
            libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
            _ => CryptoError::SigningError,
        })
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;
        libcrux_ed25519::sign(data, key)
            .map_err(|_| CryptoError::SigningError)
            .map(|sig| sig.to_vec())
    }

    fn hpke_seal(
        &self,
        ciphersuite: Ciphersuite,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut config = hpke_config(ciphersuite)?;

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (kem_output, ciphertext) = config
            .seal(&pk_r, info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::SenderSetupError,
                _ => CryptoError::HpkeEncryptionError,
            })?;

        let kem_output = kem_output.into();
        let ciphertext = ciphertext.into();

        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_open(
        &self,
        ciphersuite: Ciphersuite,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let config = hpke_config(ciphersuite)?;

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        config
            .open(
                input.kem_output.as_ref(),
                &sk_r,
                info,
                aad,
                input.ciphertext.as_ref(),
                None,
                None,
                None,
            )
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::ReceiverSetupError,
                _ => CryptoError::HpkeDecryptionError,
            })
    }

    fn hpke_setup_sender_and_export(
        &self,
        ciphersuite: Ciphersuite,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        let mut config = hpke_config(ciphersuite)?;

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (enc, ctx) = config
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(|exported| (enc, exported.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        ciphersuite: Ciphersuite,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let config = hpke_config(ciphersuite)?;

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        let ctx = config
            .setup_receiver(enc, &sk_r, info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(ExporterSecret::from)
    }

    fn derive_hpke_keypair(
        &self,
        ciphersuite: Ciphersuite,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let config = hpke_config(ciphersuite)?;

        let key_pair: hpke_rs::HpkeKeyPair = config.derive_key_pair(ikm).map_err(|e| match e {
            hpke_rs::HpkeError::InvalidConfig => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        let (sk, pk) = key_pair.into_keys();

        Ok(HpkeKeyPair {
            private: sk.as_slice().to_vec().into(),
            public: pk.as_slice().to_vec(),
        })
    }
}

fn hpke_config(ciphersuite: Ciphersuite) -> Result<hpke_rs::Hpke<HpkeLibcrux>, CryptoError> {
    let kem = hpke_kem(ciphersuite)?;
    let kdf = hpke_kdf(ciphersuite)?;
    let aead = hpke_aead(ciphersuite)?;

    Ok(hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead))
}

fn hpke_kdf(ciphersuite: Ciphersuite) -> Result<hpke_rs_crypto::types::KdfAlgorithm, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256)
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha384)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha512)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn hpke_kem(ciphersuite: Ciphersuite) -> Result<hpke_rs_crypto::types::KemAlgorithm, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem25519)
        }
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP256)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem448)
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP384)
        }
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP521)
        }
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(hpke_rs_crypto::types::KemAlgorithm::XWingDraft06)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn hpke_aead(ciphersuite: Ciphersuite) -> Result<hpke_rs_crypto::types::AeadAlgorithm, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
            Ok(hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm)
        }
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(hpke_rs_crypto::types::AeadAlgorithm::ChaCha20Poly1305)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
            Ok(hpke_rs_crypto::types::AeadAlgorithm::Aes256Gcm)
        }
        Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            Ok(hpke_rs_crypto::types::AeadAlgorithm::ChaCha20Poly1305)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn hkdf_alg(ciphersuite: Ciphersuite) -> Result<libcrux_hkdf::Algorithm, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(libcrux_hkdf::Algorithm::Sha256)
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            Ok(libcrux_hkdf::Algorithm::Sha384)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            Ok(libcrux_hkdf::Algorithm::Sha512)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn hash_alg(ciphersuite: Ciphersuite) -> Result<libcrux_hmac::Algorithm, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(libcrux_hmac::Algorithm::Sha256)
        }
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            Ok(libcrux_hmac::Algorithm::Sha384)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            Ok(libcrux_hmac::Algorithm::Sha512)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn aead_alg(ciphersuite: Ciphersuite) -> Result<libcrux_aead::Aead, CryptoError> {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
        | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(libcrux_aead::Aead::ChaCha20Poly1305)
        }
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
            Ok(libcrux_aead::Aead::AesGcm128)
        }
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
            Ok(libcrux_aead::Aead::AesGcm256)
        }
        Ciphersuite::Custom(_) => Err(CryptoError::UnsupportedCiphersuite),
    }
}

struct GuardedRng<'a, Rng: RngCore>(MutexGuard<'a, Rng>);

impl<Rng: RngCore> RngCore for GuardedRng<'_, Rng> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}

impl<Rng: RngCore + CryptoRng> CryptoRng for GuardedRng<'_, Rng> {}
