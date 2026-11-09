use super::*;
use p256::ecdsa::{VerifyingKey, signature::Verifier};

/// Fixed accepted-state transcript (`cssr.accepted-state.v2`, community [1;32],
/// identity [5;32], owner [2;32], state [3;32], scope [4;32], version 7, accepted_at 120), signed
/// with issuer key [3;32]. cblc's tests verify these exact bytes with its own
/// encoder, so any divergence between signer and verifier is detected there.
const GOLDEN_TRANSCRIPT: &str = "637373722e61636365707465642d73746174652e7632000101010101010101010101010101010101010101010101010101010101010101050505050505050505050505050505050505050505050505050505050505050502020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000000070000000000000078";
const GOLDEN_PUBLIC_KEY: &str = "591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0";
const GOLDEN_SIGNATURE: &str = "5d7dce889d4477d54367b52f8182d46fe42e32b0ade5ff27213dc2d4df38921323c1d7e787bbf99db619b8bd4f716d2fe6715d4c934466931d9eac98f96519a3";

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
    // czkp owns the format: its encoder must produce the pinned transcript that
    // this issuer signs, so signer and verifier cannot drift apart.
    let transcript = czkp::certificate::AcceptedState {
        community: [1; 32],
        identity: [5; 32],
        owner: [2; 32],
        state: [3; 32],
        scope: [4; 32],
        version: 7,
        accepted_at: 120,
    }
    .bytes();
    assert_eq!(transcript, hex(GOLDEN_TRANSCRIPT));
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

/// Known-answer vectors for the P-256 primitives the issuer runs secret scalars through
/// (RFC 6979 A.2.5 key and messages, the golden issuer key [3;32], and the largest valid
/// scalar n-1). Pinned before any p256 upgrade: every byte must stay identical across
/// versions, so a change in nonce derivation, scalar arithmetic, low-S normalization or
/// SEC1/DER/PKCS#8 encoding fails here. Values cross-checked against OpenSSL (equal except
/// where noted: OpenSSL's SEC1 private key carries the optional curve parameters).
mod vectors {
    use super::{CertificateIssuer, hex};
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    use p256::{PublicKey, SecretKey};

    struct Key {
        secret: &'static str,
        uncompressed: &'static str,
        compressed: &'static str,
        /// RustCrypto's SEC1 ECPrivateKey (no optional curve parameters).
        sec1_der: &'static str,
        /// OpenSSL's form of the same key (with the optional parameters); must decode.
        openssl_sec1_der: &'static str,
        pkcs8_der: &'static str,
        spki_der: &'static str,
    }

    struct Vector {
        secret: &'static str,
        message: &'static [u8],
        /// Plain RFC 6979 output (r || s), before low-S normalization.
        raw: &'static str,
        raw_der: &'static str,
        /// What `CertificateIssuer::sign` emits: r || min(s, n - s).
        low: &'static str,
        low_der: &'static str,
    }

    const RFC_SECRET: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const GOLDEN_SECRET: &str = "0303030303030303030303030303030303030303030303030303030303030303";
    const MAX_SECRET: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    const KEYS: [Key; 3] = [
        Key {
            secret: RFC_SECRET,
            uncompressed: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            compressed: "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            sec1_der: "306b0201010420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721a1440342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            openssl_sec1_der: "30770201010420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721a00a06082a8648ce3d030107a1440342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            pkcs8_der: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721a1440342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            spki_der: "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        },
        Key {
            secret: GOLDEN_SECRET,
            uncompressed: "04591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0",
            compressed: "02591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf",
            sec1_der: "306b02010104200303030303030303030303030303030303030303030303030303030303030303a14403420004591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0",
            openssl_sec1_der: "307702010104200303030303030303030303030303030303030303030303030303030303030303a00a06082a8648ce3d030107a14403420004591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0",
            pkcs8_der: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200303030303030303030303030303030303030303030303030303030303030303a14403420004591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0",
            spki_der: "3059301306072a8648ce3d020106082a8648ce3d03010703420004591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0",
        },
        Key {
            secret: MAX_SECRET,
            uncompressed: "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            compressed: "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            sec1_der: "306b0201010420ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550a144034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            openssl_sec1_der: "30770201010420ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550a00a06082a8648ce3d030107a144034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            pkcs8_der: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550a144034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            spki_der: "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
        },
    ];

    const VECTORS: [Vector; 4] = [
        Vector {
            secret: RFC_SECRET,
            message: b"sample",
            raw: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            raw_der: "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            low: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf37160834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
            low_der: "3045022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf371602200834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
        },
        Vector {
            secret: RFC_SECRET,
            message: b"test",
            raw: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            raw_der: "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d383670220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            low: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            low_der: "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d383670220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
        },
        Vector {
            secret: GOLDEN_SECRET,
            message: b"sample",
            raw: "0291690f88e8b93c7f2dd1f4e86b2b8907f7a355b7ccbb4832d2512d164f951cb860d044a07c8f75f3c2a86c60effe91bc6ab71a1544c325f6bf5d0dde055743",
            raw_der: "304502200291690f88e8b93c7f2dd1f4e86b2b8907f7a355b7ccbb4832d2512d164f951c022100b860d044a07c8f75f3c2a86c60effe91bc6ab71a1544c325f6bf5d0dde055743",
            low: "0291690f88e8b93c7f2dd1f4e86b2b8907f7a355b7ccbb4832d2512d164f951c479f2fba5f83708b0c3d57939f10016e007c439391d2db5efcfa6db51e5dce0e",
            low_der: "304402200291690f88e8b93c7f2dd1f4e86b2b8907f7a355b7ccbb4832d2512d164f951c0220479f2fba5f83708b0c3d57939f10016e007c439391d2db5efcfa6db51e5dce0e",
        },
        Vector {
            secret: MAX_SECRET,
            message: b"sample",
            raw: "a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ceb783aa569666ddbb05d0a5b9ce18b2757b27e2f6a4b4b1a3e4b4ced21f4174b2",
            raw_der: "3046022100a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ce022100b783aa569666ddbb05d0a5b9ce18b2757b27e2f6a4b4b1a3e4b4ced21f4174b2",
            low: "a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ce487c55a869992245fa2f5a4631e74d8a41bf17b70262ece10f04fbf0dd21b09f",
            low_der: "3045022100a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ce0220487c55a869992245fa2f5a4631e74d8a41bf17b70262ece10f04fbf0dd21b09f",
        },
    ];

    fn signing_key(secret: &str) -> SigningKey {
        SigningKey::from_slice(&hex(secret)).unwrap()
    }

    fn secret_array(secret: &str) -> [u8; 32] {
        hex(secret).try_into().unwrap()
    }

    #[test]
    fn rfc6979_signatures_are_pinned_bytes() {
        for vector in &VECTORS {
            let key = signing_key(vector.secret);
            let raw: Signature = key.sign(vector.message);
            assert_eq!(raw.to_bytes().to_vec(), hex(vector.raw));
            assert_eq!(raw.to_der().as_bytes().to_vec(), hex(vector.raw_der));
            // The issuer emits the canonical low-S form of the same deterministic signature.
            let issuer = CertificateIssuer::new(&secret_array(vector.secret)).unwrap();
            let issued = issuer.sign(vector.message);
            assert_eq!(issued.to_vec(), hex(vector.low));
            let low = Signature::from_slice(&issued).unwrap();
            assert_eq!(low.to_der().as_bytes().to_vec(), hex(vector.low_der));
        }
    }

    #[test]
    fn stored_signatures_decode_and_verify() {
        for vector in &VECTORS {
            let key = *signing_key(vector.secret).verifying_key();
            for (bytes, der) in [(vector.raw, vector.raw_der), (vector.low, vector.low_der)] {
                let fixed = Signature::from_slice(&hex(bytes)).unwrap();
                let decoded = Signature::from_der(&hex(der)).unwrap();
                assert_eq!(fixed, decoded);
                // The plain verifier accepts both S forms (P-256 has no low-S rule); the
                // canonical-form rule is the caller's (see `verify` above).
                assert!(key.verify(vector.message, &fixed).is_ok());
                let mut other = vector.message.to_vec();
                other[0] ^= 1;
                assert!(key.verify(&other, &fixed).is_err());
            }
        }
        // The golden issuer signature stored above verifies with the plain verifier.
        let key =
            VerifyingKey::from_sec1_bytes(&[&[4][..], &hex(super::GOLDEN_PUBLIC_KEY)].concat())
                .unwrap();
        let signature = Signature::from_slice(&hex(super::GOLDEN_SIGNATURE)).unwrap();
        assert!(
            key.verify(&hex(super::GOLDEN_TRANSCRIPT), &signature)
                .is_ok()
        );
        // Malformed DER is refused.
        let mut der = hex(VECTORS[0].raw_der);
        der[1] ^= 1;
        assert!(Signature::from_der(&der).is_err());
    }

    #[test]
    fn key_encodings_are_pinned_bytes() {
        for key in &KEYS {
            let secret = SecretKey::from_slice(&hex(key.secret)).unwrap();
            assert_eq!(secret.to_bytes().to_vec(), hex(key.secret));
            assert_eq!(secret.to_sec1_der().unwrap().to_vec(), hex(key.sec1_der));
            assert_eq!(
                secret.to_pkcs8_der().unwrap().as_bytes().to_vec(),
                hex(key.pkcs8_der)
            );
            assert_eq!(
                SecretKey::from_sec1_der(&hex(key.sec1_der))
                    .unwrap()
                    .to_bytes(),
                secret.to_bytes()
            );
            assert_eq!(
                SecretKey::from_sec1_der(&hex(key.openssl_sec1_der))
                    .unwrap()
                    .to_bytes(),
                secret.to_bytes()
            );
            assert_eq!(
                SecretKey::from_pkcs8_der(&hex(key.pkcs8_der))
                    .unwrap()
                    .to_bytes(),
                secret.to_bytes()
            );

            let public = secret.public_key();
            assert_eq!(public.to_sec1_bytes().to_vec(), hex(key.uncompressed));
            assert_eq!(
                public.to_public_key_der().unwrap().as_bytes().to_vec(),
                hex(key.spki_der)
            );
            assert_eq!(
                PublicKey::from_public_key_der(&hex(key.spki_der)).unwrap(),
                public
            );
            for encoded in [key.uncompressed, key.compressed] {
                assert_eq!(PublicKey::from_sec1_bytes(&hex(encoded)).unwrap(), public);
                assert_eq!(
                    VerifyingKey::from_sec1_bytes(&hex(encoded)).unwrap(),
                    *signing_key(key.secret).verifying_key()
                );
            }
            assert_eq!(
                VerifyingKey::from(&public)
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                hex(key.compressed)
            );

            let issuer = CertificateIssuer::new(&secret_array(key.secret)).unwrap();
            assert_eq!(
                issuer.public_key().to_vec(),
                hex(key.uncompressed)[1..].to_vec()
            );
        }
    }

    #[test]
    fn issuer_secret_range_is_pinned() {
        // Accepted: 1 and n-1. Refused: 0, n, and 2^256-1 (no reduction mod n).
        let mut one = [0; 32];
        one[31] = 1;
        assert!(CertificateIssuer::new(&one).is_ok());
        assert!(CertificateIssuer::new(&secret_array(MAX_SECRET)).is_ok());
        assert!(CertificateIssuer::new(&[0; 32]).is_err());
        assert!(CertificateIssuer::new(&secret_array(ORDER)).is_err());
        assert!(CertificateIssuer::new(&[255; 32]).is_err());
        // A point off the curve and an invalid SEC1 tag are refused.
        let mut off = hex(KEYS[0].uncompressed);
        off[64] ^= 1;
        assert!(VerifyingKey::from_sec1_bytes(&off).is_err());
        let mut tag = hex(KEYS[0].compressed);
        tag[0] = 1;
        assert!(VerifyingKey::from_sec1_bytes(&tag).is_err());
    }
}
