//! The bridge to `alice-crypto`'s `dp` module actually carries noise.
//!
//! The law itself — unpredictability, reproducibility, the Laplace mean and
//! variance, the RFC 8439 keystream — is pinned upstream in
//! `alice-crypto/tests/dp_noise_oracle.rs`. ⚠️ Copying those assertions here
//! would recreate exactly what this change removed: the same law in two places,
//! which is the same law getting fixed once.
//!
//! What this file checks instead is the part that is this crate's own: that the
//! re-export resolves, that the names callers used before still work, and that
//! noise reaches the output rather than the call being a pass-through. A
//! re-export that compiles but is never exercised is how a dependency gets
//! "wired" on paper only.

use alice_datashield::differential_privacy::{dp_count, dp_sum, DpNoise, SecureRng};

#[test]
fn the_reexported_names_are_usable_from_this_crate() {
    // Reached through this crate's path, not the upstream one.
    let mut rng = SecureRng::from_key([7u8; 32]);
    let counted: i64 = dp_count(1_000, 1.0, &mut rng).expect("eps = 1 is valid");
    let summed = dp_sum(500.0, 10.0, 1.0, &mut rng).expect("valid arguments");
    assert!((counted - 1_000).abs() < 1_000 && summed.is_finite());

    let mut noise = DpNoise::with_key(1.0, 1.0, [9u8; 32]);
    assert!(noise.privatize(0.0).expect("in range").is_finite());
    assert_eq!((noise.sensitivity(), noise.epsilon()), (1.0, 1.0));
}

/// 20 noisy counts with one key
fn counts(key: u8) -> Vec<i64> {
    let mut rng = SecureRng::from_key([key; 32]);
    (0..20).map(|_| dp_count(1_000, 1.0, &mut rng).expect("valid")).collect()
}

#[test]
fn noise_reaches_the_output_and_is_reproducible_through_this_crate() {
    // Not a pass-through: discrete Laplace puts mass ≈ 0.46 on 0 at ε = 1, so
    // one count may come back unchanged, 20 all unchanged has probability < 2^-22
    let noisy = counts(13);
    assert!(noisy.iter().any(|&c| c != 1_000), "dp_count returned the true count unchanged");

    // Same key and call order, same answers — what an audit rests on.
    assert_eq!(counts(13), noisy);

    // A different key gives different answers, so the key is load-bearing.
    assert_ne!(counts(14), noisy);
}

#[test]
fn invalid_parameters_are_refused_through_this_crate_too() {
    let mut rng = SecureRng::from_key([19u8; 32]);
    assert!(dp_count(1, 0.0, &mut rng).is_err());
    assert!(dp_count(1, f64::NAN, &mut rng).is_err());
    assert!(dp_sum(1.0, 0.0, 1.0, &mut rng).is_err());
    assert!(DpNoise::try_with_key(-1.0, 1.0, [1u8; 32]).is_err());
}
