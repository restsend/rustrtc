//! Pure-Rust (p256) reference implementation of the DTLS crypto seam.

use super::crypto::{DtlsCrypto, EcdhSecret, SigningKey, VerifyingKey};
use crate::errors::RtcResult as Result;
use alloc::boxed::Box;
use alloc::vec::Vec;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::{RandomizedSigner, Verifier};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;

/// `rand_core` adapter over the platform RNG seam, for p256's randomized
/// signing.
pub struct PlatformRng;

impl p256::elliptic_curve::rand_core::RngCore for PlatformRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        crate::platform::rng::fill(&mut b);
        u32::from_be_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        crate::platform::rng::fill(&mut b);
        u64::from_be_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::platform::rng::fill(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> core::result::Result<(), p256::elliptic_curve::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl p256::elliptic_curve::rand_core::CryptoRng for PlatformRng {}

fn err(msg: alloc::string::String) -> crate::errors::RtcError {
    crate::errors::RtcError::Internal(msg)
}

struct P256SigningKey(p256::ecdsa::SigningKey);

impl SigningKey for P256SigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.0.sign_with_rng(&mut PlatformRng, msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn verifying_key(&self) -> Result<Box<dyn VerifyingKey>> {
        Ok(Box::new(P256VerifyingKey(self.0.verifying_key().clone())))
    }
}

struct P256VerifyingKey(p256::ecdsa::VerifyingKey);

impl VerifyingKey for P256VerifyingKey {
    fn verify(&self, msg: &[u8], signature_der: &[u8]) -> Result<()> {
        let signature = Signature::from_der(signature_der)
            .map_err(|e| err(alloc::format!("invalid signature: {e}")))?;
        self.0
            .verify(msg, &signature)
            .map_err(|e| err(alloc::format!("signature verify failed: {e}")))
    }
}

struct P256EcdhSecret(p256::ecdh::EphemeralSecret);

impl EcdhSecret for P256EcdhSecret {
    fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
        let peer = p256::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|e| err(alloc::format!("bad peer point: {e}")))?;
        Ok(self.0.diffie_hellman(&peer).raw_secret_bytes().to_vec())
    }
}

/// Reference backend backed by p256.
pub struct P256Crypto;

impl DtlsCrypto for P256Crypto {
    fn signing_key_from_pkcs8_der(&self, der: &[u8]) -> Result<Box<dyn SigningKey>> {
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|e| err(alloc::format!("bad pkcs8 key: {e}")))?;
        Ok(Box::new(P256SigningKey(key)))
    }

    fn verifying_key_from_point(&self, point: &[u8]) -> Result<Box<dyn VerifyingKey>> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| err(alloc::format!("bad EC point: {e}")))?;
        Ok(Box::new(P256VerifyingKey(key)))
    }

    fn ecdh_generate(&self) -> Result<(Vec<u8>, Box<dyn EcdhSecret>)> {
        let secret = p256::ecdh::EphemeralSecret::random(&mut PlatformRng);
        let public = Vec::from(secret.public_key().to_encoded_point(false).as_bytes());
        Ok((public, Box::new(P256EcdhSecret(secret))))
    }
}
