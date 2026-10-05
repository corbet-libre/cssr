//! Circuit-readable certificates for accepted opaque states, using RustCrypto P-256.
//! The facade owns proof verification and must return certificates only after commit.
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
        czkp::compact::message(&bytes)
    }
}

/// Private minimum-frontier ancestry statement, distinct from a state certificate.
/// The accounting facade proves ancestry by its linear state/inbox transaction.
/// This body alone is never evidence of ancestry or a public member record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EpochAncestry {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped account owner, hidden in the eventual record proof.
    pub owner: [u8; 32],
    /// Published epoch number.
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Exact blinded frozen leaf commitment in that root.
    pub frozen_leaf: [u8; 32],
    /// Newly accepted descendant commitment.
    pub state: [u8; 32],
    /// Newly accepted version.
    pub version: u64,
    /// Original update circuit manifest digest.
    pub circuit_digest: [u8; 32],
    /// Original update verification-key digest.
    pub verifying_key_digest: [u8; 32],
    /// Acceptance time of this descendant, never refreshed on retry.
    pub issued_at: u64,
}

impl EpochAncestry {
    /// Canonical fixed-width transcript: domain, community, owner, epoch, root,
    /// frozen leaf, state, version, both proof-scope digests, issuance time.
    /// Digests are opaque here; the facade checks circuit field encodings.
    pub fn bytes(&self) -> crate::Result<Vec<u8>> {
        const MAX_INTEGER: u64 = (1 << 53) - 1;
        if self.epoch == 0
            || self.epoch > MAX_INTEGER
            || self.version > MAX_INTEGER
            || self.issued_at == 0
            || self.issued_at > MAX_INTEGER
            || [
                self.community,
                self.owner,
                self.root,
                self.frozen_leaf,
                self.state,
                self.circuit_digest,
                self.verifying_key_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(crate::Error);
        }
        let mut bytes = b"cblc.epoch-ancestry.v1\0".to_vec();
        bytes.extend_from_slice(&self.community);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.frozen_leaf);
        bytes.extend_from_slice(&self.state);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.circuit_digest);
        bytes.extend_from_slice(&self.verifying_key_digest);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(czkp::compact::message(&bytes))
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

    /// Sign inside the facade's verified acceptance CAS; do not expose on rollback.
    pub fn issue_ancestry(&self, body: &EpochAncestry) -> crate::Result<[u8; 64]> {
        let signature: Signature = self.0.sign(&body.bytes()?);
        Ok(signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into())
    }
}

/// Check a certificate, rejecting high-S aliases and malformed public keys.
pub fn verify(key: &[u8; 64], accepted: &AcceptedState, signature: &[u8; 64]) -> crate::Result<()> {
    verify_bytes(key, &accepted.bytes(), signature)
}

/// Verify canonical ancestry bytes with the original issuer's P-256 key.
/// The consumer must separately bind the expected epoch, owner and scope.
pub fn verify_ancestry(
    key: &[u8; 64],
    body: &EpochAncestry,
    signature: &[u8; 64],
) -> crate::Result<()> {
    verify_bytes(key, &body.bytes()?, signature)
}

fn verify_bytes(key: &[u8; 64], bytes: &[u8], signature: &[u8; 64]) -> crate::Result<()> {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    let key = VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| crate::Error)?;
    let signature = Signature::from_slice(signature).map_err(|_| crate::Error)?;
    if signature.normalize_s().is_some() {
        return Err(crate::Error);
    }
    key.verify(bytes, &signature).map_err(|_| crate::Error)
}

#[cfg(test)]
#[path = "../tests/internal/certificate.rs"]
mod tests;
