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
