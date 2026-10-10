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
