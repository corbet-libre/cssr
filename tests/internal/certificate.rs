use super::*;
#[test]
fn certificate_binds_every_accepted_state_field() {
    let issuer = CertificateIssuer::new(&[3; 32]).unwrap();
    let body = AcceptedState {
        community: [1; 32],
        owner: [2; 32],
        state: [3; 32],
        scope: [4; 32],
        version: 7,
        accepted_at: 120,
    };
    let signature = issuer.issue(&body);
    verify(&issuer.public_key(), &body, &signature).unwrap();
    assert_eq!(signature, issuer.issue(&body));
    for field in 0..6 {
        let mut changed = body;
        match field {
            0 => changed.community[0] ^= 1,
            1 => changed.owner[0] ^= 1,
            2 => changed.state[0] ^= 1,
            3 => changed.scope[0] ^= 1,
            4 => changed.version += 1,
            _ => changed.accepted_at += 1,
        }
        assert!(verify(&issuer.public_key(), &changed, &signature).is_err());
    }
    let other = CertificateIssuer::new(&[4; 32]).unwrap();
    assert!(verify(&other.public_key(), &body, &signature).is_err());
    assert!(CertificateIssuer::new(&[0; 32]).is_err());
    assert!(verify(&[0; 64], &body, &signature).is_err());
    assert!(verify(&issuer.public_key(), &body, &[0; 64]).is_err());
    // A high-S alias has a valid mathematical signature but a second wire
    // encoding. The issuer requires the canonical low-S form.
    let canonical = Signature::from_slice(&signature).unwrap();
    let (r, s) = canonical.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    assert!(verify(&issuer.public_key(), &body, &high.to_bytes().into()).is_err());
}

fn ancestry() -> EpochAncestry {
    EpochAncestry {
        community: [1; 32],
        owner: [2; 32],
        epoch: 3,
        root: [4; 32],
        frozen_leaf: [5; 32],
        state: [6; 32],
        version: 7,
        circuit_digest: [8; 32],
        verifying_key_digest: [9; 32],
        issued_at: 10,
    }
}

#[test]
fn ancestry_transcript_vector_and_every_field_are_bound() {
    let body = ancestry();
    let original = concat!(
        "63626c632e65706f63682d616e6365737472792e763100",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0000000000000003",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "0505050505050505050505050505050505050505050505050505050505050505",
        "0606060606060606060606060606060606060606060606060606060606060606",
        "0000000000000007",
        "0808080808080808080808080808080808080808080808080808080808080808",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "000000000000000a",
    );
    let raw: Vec<u8> = (0..original.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&original[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(body.bytes().unwrap(), czkp::compact::message(&raw));
    let issuer = CertificateIssuer::new(&[3; 32]).unwrap();
    let signature = issuer.issue_ancestry(&body).unwrap();
    verify_ancestry(&issuer.public_key(), &body, &signature).unwrap();
    assert_eq!(signature, issuer.issue_ancestry(&body).unwrap());
    for field in 0..10 {
        let mut changed = body;
        match field {
            0 => changed.community[0] ^= 1,
            1 => changed.owner[0] ^= 1,
            2 => changed.epoch += 1,
            3 => changed.root[0] ^= 1,
            4 => changed.frozen_leaf[0] ^= 1,
            5 => changed.state[0] ^= 1,
            6 => changed.version += 1,
            7 => changed.circuit_digest[0] ^= 1,
            8 => changed.verifying_key_digest[0] ^= 1,
            _ => changed.issued_at += 1,
        }
        assert!(verify_ancestry(&issuer.public_key(), &changed, &signature).is_err());
    }
    assert!(
        verify_ancestry(
            &CertificateIssuer::new(&[4; 32]).unwrap().public_key(),
            &body,
            &signature
        )
        .is_err()
    );
    assert!(verify_ancestry(&[0; 64], &body, &signature).is_err());
    assert!(verify_ancestry(&issuer.public_key(), &body, &[0; 64]).is_err());
    let canonical = Signature::from_slice(&signature).unwrap();
    let (r, s) = canonical.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    assert!(verify_ancestry(&issuer.public_key(), &body, &high.to_bytes().into()).is_err());
    let accepted = AcceptedState {
        community: body.community,
        owner: body.owner,
        state: body.state,
        scope: body.circuit_digest,
        version: body.version,
        accepted_at: body.issued_at,
    };
    assert!(verify(&issuer.public_key(), &accepted, &signature).is_err());
    assert!(verify_ancestry(&issuer.public_key(), &body, &issuer.issue(&accepted)).is_err());
}

#[test]
fn malformed_ancestry_bounds_cannot_be_signed_or_verified() {
    let issuer = CertificateIssuer::new(&[3; 32]).unwrap();
    let signature = issuer.issue_ancestry(&ancestry()).unwrap();
    for field in 0..12 {
        let mut body = ancestry();
        match field {
            0 => body.community = [0; 32],
            1 => body.owner = [0; 32],
            2 => body.root = [0; 32],
            3 => body.frozen_leaf = [0; 32],
            4 => body.state = [0; 32],
            5 => body.circuit_digest = [0; 32],
            6 => body.verifying_key_digest = [0; 32],
            7 => body.epoch = 0,
            8 => body.epoch = 1 << 53,
            9 => body.version = 1 << 53,
            10 => body.issued_at = 0,
            _ => body.issued_at = 1 << 53,
        }
        assert!(body.bytes().is_err());
        assert!(issuer.issue_ancestry(&body).is_err());
        assert!(verify_ancestry(&issuer.public_key(), &body, &signature).is_err());
    }
    let mut boundary = ancestry();
    boundary.epoch = (1 << 53) - 1;
    boundary.version = 0;
    boundary.issued_at = (1 << 53) - 1;
    let signature = issuer.issue_ancestry(&boundary).unwrap();
    verify_ancestry(&issuer.public_key(), &boundary, &signature).unwrap();
}

#[test]
fn record_issuer_binds_same_frozen_and_descendant_transcript() {
    let issuer = super::RecordIssuer::new(&[19; 32]);
    let leaf = [1; 32];
    let signature = issuer.issue(&[2; 32], 3, &leaf).unwrap();
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
}
