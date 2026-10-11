use super::*;
use p256::ecdsa::{VerifyingKey, signature::Verifier};

/// Fixed accepted-state transcript (`cssr.accepted-state.v1`, community [1;32],
/// owner [2;32], state [3;32], scope [4;32], version 7, accepted_at 120), signed
/// with issuer key [3;32]. cblc's tests verify these exact bytes with its own
/// encoder, so any divergence between signer and verifier is detected there.
const GOLDEN_TRANSCRIPT: &str = "637373722e61636365707465642d73746174652e763100010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000000070000000000000078";
const GOLDEN_PUBLIC_KEY: &str = "591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0";
const GOLDEN_SIGNATURE: &str = "902f3030e007662ec00bdb101b6d1205c1d4c461816911db73e1b5d5235e1ed50f5f13410b15d71e59e5eafd6530be144df21ac9729aadbd05625edb52a826bc";

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn verify(key: &[u8; 64], bytes: &[u8], signature: &[u8; 64]) -> bool {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&encoded) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    signature.normalize_s().is_none() && key.verify(bytes, &signature).is_ok()
}

#[test]
fn issuer_signs_the_golden_transcript_with_the_fixed_canonical_signature() {
    let issuer = CertificateIssuer::new(&[3; 32]).unwrap();
    assert_eq!(issuer.public_key().to_vec(), hex(GOLDEN_PUBLIC_KEY));
    let transcript = hex(GOLDEN_TRANSCRIPT);
    let signature = issuer.sign(&transcript);
    assert_eq!(signature.to_vec(), hex(GOLDEN_SIGNATURE));
    assert!(verify(&issuer.public_key(), &transcript, &signature));
    // Deterministic, and bound to every transcript byte and to the key.
    assert_eq!(signature, issuer.sign(&transcript));
    for index in 0..transcript.len() {
        let mut changed = transcript.clone();
        changed[index] ^= 1;
        assert!(!verify(&issuer.public_key(), &changed, &signature));
    }
    let other = CertificateIssuer::new(&[4; 32]).unwrap();
    assert!(!verify(&other.public_key(), &transcript, &signature));
    assert!(CertificateIssuer::new(&[0; 32]).is_err());
    // A high-S alias is a second wire encoding; canonical low-S is required.
    let canonical = Signature::from_slice(&signature).unwrap();
    let (r, s) = canonical.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    assert!(!verify(
        &issuer.public_key(),
        &transcript,
        &high.to_bytes().into()
    ));
}

#[test]
fn record_issuer_binds_same_frozen_and_descendant_transcript() {
    let issuer = super::RecordIssuer::new(&[19; 32]);
    let leaf = [1; 32];
    let signature = issuer.issue(&[2; 32], 3, &leaf).unwrap();
    assert_eq!(signature, issuer.issue(&[2; 32], 3, &leaf).unwrap());
    czkp::record::verify_certificate(&issuer.public_key(), &[2; 32], 3, &leaf, &signature).unwrap();
    for case in 0..7 {
        let mut key = issuer.public_key();
        let mut community = [2; 32];
        let mut epoch = 3;
        let mut leaf = leaf;
        let mut signature = signature;
        match case {
            0 => key[0] ^= 1,
            1 => community[0] ^= 1,
            2 => epoch += 1,
            3 => leaf[0] ^= 1,
            4 => signature[0] ^= 1,
            5 => signature[32..].fill(255),
            _ => signature[..32].fill(0),
        }
        assert!(
            czkp::record::verify_certificate(&key, &community, epoch, &leaf, &signature).is_err()
        );
    }
    for leaf in [[0; 32], [255; 32]] {
        assert!(issuer.issue(&[2; 32], 3, &leaf).is_err());
    }
    assert!(issuer.issue(&[0; 32], 3, &[1; 32]).is_err());
    assert!(issuer.issue(&[2; 32], 0, &[1; 32]).is_err());
    assert!(
        issuer
            .issue(&[2; 32], czkp::MAX_INTEGER + 1, &[1; 32])
            .is_err()
    );
    let boundary = issuer.issue(&[2; 32], czkp::MAX_INTEGER, &[1; 32]).unwrap();
    czkp::record::verify_certificate(
        &issuer.public_key(),
        &[2; 32],
        czkp::MAX_INTEGER,
        &[1; 32],
        &boundary,
    )
    .unwrap();
}
