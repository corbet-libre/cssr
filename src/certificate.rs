//! Canonical P-256 signing of accepted-state and ancestry transcripts. The transcripts
//! and their verification are owned by cblc; this module only signs bytes it is given.
//! The facade may issue these only after its verified state transaction commits.
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

/// Private issuer key; neither cloning nor exporting its secret is supported.
pub struct CertificateIssuer(SigningKey);
impl CertificateIssuer {
    /// Import an independently generated issuer key from host configuration.
    pub fn new(secret: &[u8; 32]) -> crate::Result<Self> {
        SigningKey::from_slice(secret)
            .map(Self)
            .map_err(|_| crate::Error)
    }
    /// Uncompressed affine coordinates, without the SEC1 prefix.
    pub fn public_key(&self) -> [u8; 64] {
        let encoded = self.0.verifying_key().to_encoded_point(false);
        let mut key = [0; 64];
        key.copy_from_slice(&encoded.as_bytes()[1..]);
        key
    }
    /// Sign one canonical transcript that the account owner (cblc) encoded. This
    /// issuer owns no signed format: it only produces the canonical low-S P-256
    /// signature. The caller verified and atomically accepted the state first.
    pub fn sign(&self, transcript: &[u8]) -> [u8; 64] {
        let signature: Signature = self.0.sign(transcript);
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into()
    }
}

/// Maintained Ed25519 signing for blinded record leaves. The facade must enforce
/// complete required-inbox consumption and commit the returned object atomically.
pub struct RecordIssuer(ed25519_dalek::SigningKey);
impl RecordIssuer {
    /// Use the authenticated operator's existing Ed25519 seed with a distinct domain.
    pub fn new(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }
    /// Public key carried inside the authenticated common epoch descriptor.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    /// Sign the identical format for a frozen or necessarily descended leaf.
    pub fn issue(
        &self,
        community: &[u8; 32],
        epoch: u64,
        leaf: &[u8; 32],
    ) -> crate::Result<[u8; 64]> {
        let bytes =
            czkp::record::certificate_bytes(community, epoch, leaf).map_err(|_| crate::Error)?;
        Ok(ed25519_dalek::Signer::sign(&self.0, &bytes).to_bytes())
    }
}

#[cfg(test)]
#[path = "../tests/internal/certificate.rs"]
mod tests;
