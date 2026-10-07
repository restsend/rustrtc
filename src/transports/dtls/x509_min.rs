//! Minimal DER walk over an X.509 certificate to pull the EC point out of
//! its SubjectPublicKeyInfo. Replaces the x509-parser dependency: the DTLS
//! profile only ever deals with self-signed/pre-provisioned P-256 certs, so
//! no chain validation or general-purpose X.509 parsing is needed here.

use super::{Result, bail};
use alloc::vec::Vec;

/// Parses one DER TLV, returning `(tag, contents, rest)`.
fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        bail!("DER: truncated header");
    }
    let tag = input[0];
    let first = input[1];
    let mut idx = 2;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < idx + n {
            bail!("DER: unsupported length encoding");
        }
        let mut l = 0usize;
        for byte in &input[idx..idx + n] {
            l = (l << 8) | *byte as usize;
        }
        idx += n;
        l
    };
    if input.len() < idx + len {
        bail!("DER: contents overrun");
    }
    Ok((tag, &input[idx..idx + len], &input[idx + len..]))
}

fn expect<'a>(input: &'a [u8], tag: u8, what: &'static str) -> Result<(&'a [u8], &'a [u8])> {
    let (t, contents, rest) = tlv(input)?;
    if t != tag {
        bail!(
            "DER: expected tag {:#04x} for {}, got {:#04x}",
            tag,
            what,
            t
        );
    }
    Ok((contents, rest))
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Extracts the uncompressed EC point of the certificate's
/// SubjectPublicKeyInfo, requiring id-ecPublicKey + prime256v1.
pub(crate) fn extract_p256_point(certificate_der: &[u8]) -> Result<Vec<u8>> {
    let (cert, _) = expect(certificate_der, 0x30, "Certificate")?;
    let (tbs, _) = expect(cert, 0x30, "tbsCertificate")?;

    let mut rest = tbs;
    // version [0] EXPLICIT — optional (defaults to v1)
    if rest.first() == Some(&0xa0) {
        let (_, r) = expect(rest, 0xa0, "version")?;
        rest = r;
    }
    let (_, r) = expect(rest, 0x02, "serialNumber")?;
    rest = r;
    let (_, r) = expect(rest, 0x30, "signature AlgorithmIdentifier")?;
    rest = r;
    let (_, r) = expect(rest, 0x30, "issuer")?;
    rest = r;
    let (_, r) = expect(rest, 0x30, "validity")?;
    rest = r;
    let (_, r) = expect(rest, 0x30, "subject")?;
    rest = r;

    let (spki, _) = expect(rest, 0x30, "subjectPublicKeyInfo")?;
    let (alg, spki_rest) = expect(spki, 0x30, "algorithm")?;
    let (ec_oid, alg_rest) = expect(alg, 0x06, "ecPublicKey OID")?;
    if ec_oid != OID_EC_PUBLIC_KEY {
        bail!("certificate public key is not id-ecPublicKey");
    }
    let (curve_oid, _) = expect(alg_rest, 0x06, "named curve OID")?;
    if curve_oid != OID_PRIME256V1 {
        bail!("certificate curve is not prime256v1");
    }

    let (bits, _) = expect(spki_rest, 0x03, "subjectPublicKey")?;
    if bits.is_empty() || bits[0] != 0 {
        bail!("subjectPublicKey has unexpected unused bits");
    }
    Ok(bits[1..].to_vec())
}
