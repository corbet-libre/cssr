//! Circuit-readable certificates for accepted opaque states, using RustCrypto P-256.
//! The facade may issue these only after its verified state transaction commits.
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

/// Domain-separated certificate body. No opening or counterpart enters the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedState {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped opaque account owner.
    pub owner: [u8; 32],
    /// Accepted state commitment.
    pub state: [u8; 32],
    /// Digest of the pinned extension circuit manifest.
    pub scope: [u8; 32],
    /// Accepted version.
    pub version: u64,
    /// Issuer acceptance time, hidden inside anonymous deposit proofs.
    pub accepted_at: u64,
}
impl AcceptedState {
    /// Fixed encoding also checked inside the Noir deposit relation.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = b"cssr.accepted-state.v1\0".to_vec();
        for field in [self.community, self.owner, self.state, self.scope] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.accepted_at.to_be_bytes());
        bytes
    }
}

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
    /// Sign an already accepted state. Caller owns proof verification and atomicity.
    pub fn issue(&self, accepted: &AcceptedState) -> [u8; 64] {
        let signature: Signature = self.0.sign(&accepted.bytes());
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into()
    }
}

/// Check a certificate, rejecting high-S aliases and malformed public keys.
pub fn verify(key: &[u8; 64], accepted: &AcceptedState, signature: &[u8; 64]) -> crate::Result<()> {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    let key = VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| crate::Error)?;
    let signature = Signature::from_slice(signature).map_err(|_| crate::Error)?;
    if signature.normalize_s().is_some() {
        return Err(crate::Error);
    }
    key.verify(&accepted.bytes(), &signature)
        .map_err(|_| crate::Error)
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
