//! DTLS crypto seam: ECDSA-P256-SHA256 + ECDH-P256.
//!
//! The DTLS transport calls this seam for all public-key operations. The
//! built-in pure-Rust backend (p256) is active when the `crypto-p256`
//! feature is enabled (implied by `std`); embedders can inject their own —
//! e.g. hardware-accelerated or mbedtls-backed — implementation via
//! [`set_crypto`] instead, which keeps the p256 dependency chain out of the
//! firmware entirely.

use crate::errors::RtcResult as Result;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

/// ECDSA (P-256, SHA-256) signing key. `sign` returns a DER-encoded
/// signature over SHA-256(`msg`).
pub trait SigningKey: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;

    /// Verifying key corresponding to this signing key (signature
    /// round-trip checks).
    fn verifying_key(&self) -> Result<Box<dyn VerifyingKey>>;
}

/// ECDSA (P-256, SHA-256) verifying key.
pub trait VerifyingKey: Send + Sync {
    fn verify(&self, msg: &[u8], signature_der: &[u8]) -> Result<()>;
}

/// ECDH (P-256) ephemeral secret held by the key-exchange initiator.
pub trait EcdhSecret: Send + Sync {
    /// Computes the shared secret with the peer's uncompressed SEC1 point.
    fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>>;
}

/// Crypto backend for the DTLS transport.
pub trait DtlsCrypto: Send + Sync + 'static {
    /// Restores a signing key from a PKCS#8 DER private key (P-256).
    fn signing_key_from_pkcs8_der(&self, der: &[u8]) -> Result<Box<dyn SigningKey>>;

    /// Builds a verifying key from an uncompressed SEC1 public point
    /// (`0x04 || X || Y`, 65 bytes for P-256).
    fn verifying_key_from_point(&self, point: &[u8]) -> Result<Box<dyn VerifyingKey>>;

    /// Generates an ephemeral ECDH keypair, returning the uncompressed public
    /// point and the secret.
    fn ecdh_generate(&self) -> Result<(Vec<u8>, Box<dyn EcdhSecret>)>;
}

static CRYPTO: AtomicPtr<Arc<dyn DtlsCrypto>> = AtomicPtr::new(core::ptr::null_mut());

/// Injects a crypto backend (thread-safe, leak-once). Call once during
/// startup, before any DTLS handshake.
pub fn set_crypto(impl_: Arc<dyn DtlsCrypto>) {
    let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(impl_));
    CRYPTO.store(leaked as *mut Arc<dyn DtlsCrypto>, Ordering::Release);
}

/// Active backend: the injected one if present, else the built-in p256
/// reference implementation under `crypto-p256`.
pub fn crypto() -> &'static dyn DtlsCrypto {
    let ptr = CRYPTO.load(Ordering::Acquire);
    if !ptr.is_null() {
        return unsafe { &**ptr };
    }
    #[cfg(feature = "crypto-p256")]
    {
        static REFERENCE: crate::platform::crypto_p256::P256Crypto =
            crate::platform::crypto_p256::P256Crypto;
        return &REFERENCE;
    }
    #[cfg(not(feature = "crypto-p256"))]
    panic!(
        "no DTLS crypto backend: enable the `crypto-p256` feature or call \
         platform::crypto::set_crypto before handshaking"
    );
}

#[cfg(feature = "crypto-p256")]
pub use crate::platform::crypto_p256::PlatformRng;
