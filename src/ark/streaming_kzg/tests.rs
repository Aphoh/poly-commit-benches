use ark_bls12_381_04::{Bls12_381, Fr};
use ark_poly_04::univariate::DensePolynomial;
use ark_poly_04::DenseUVPolynomial;
use ark_std_04::vec::Vec;
use ark_std_04::{UniformRand, Zero};

use crate::ark::streaming_kzg::time::CommitterKey;
use crate::ark::streaming_kzg::{vanishing_polynomial, VerifierKey};
use ark_ff_04::Field;
use ark_std_04::borrow::Borrow;

/// Polynomial evaluation, assuming that the
/// coefficients are in little-endian.
#[inline]
fn evaluate_le<F>(polynomial: &[F], x: &F) -> F
where
    F: Field,
{
    evaluate_be(polynomial.iter().rev(), x)
}

/// Polynomial evaluation, assuming that the
/// coeffients are in big-endian.
#[inline]
fn evaluate_be<I, F>(polynomial: I, x: &F) -> F
where
    F: Field,
    I: IntoIterator,
    I::Item: Borrow<F>,
{
    polynomial
        .into_iter()
        .fold(F::zero(), |previous, c| previous * x + c.borrow())
}

#[test]
fn test_open_multipoints_correctness() {
    let mut rng = &mut ark_std::test_rng();
    let d = 100;

    let eval_points = (0..5).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let polynomials = (0..15)
        .map(|_| DensePolynomial::<Fr>::rand(d, rng).coeffs)
        .collect::<Vec<_>>();
    let evals = polynomials
        .iter()
        .map(|p| {
            eval_points
                .iter()
                .map(|e| evaluate_le(p, e))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let time_ck = CommitterKey::<Bls12_381>::new(d + 1, eval_points.len(), rng);
    let time_vk = VerifierKey::from(&time_ck);

    let time_batched_commitments = time_ck.batch_commit(&polynomials);

    let eta: Fr = u128::rand(&mut rng).into();

    let proof = time_ck.batch_open_multi_points(
        &polynomials.iter().collect::<Vec<_>>()[..],
        &eval_points,
        &eta,
    );

    let verification_result = time_vk.verify_multi_points(
        &time_batched_commitments,
        &eval_points,
        &evals,
        &proof,
        &eta,
    );

    assert!(verification_result.is_ok());
}

#[test]
fn test_vanishing_polynomial() {
    use ark_bls12_381_04::Fr as F;
    use ark_ff::Zero;

    let points = [F::from(10u64), F::from(5u64), F::from(13u64)];
    let zeros = vanishing_polynomial(&points);
    assert_eq!(evaluate_le(&zeros, &points[0]), F::zero());
    assert_eq!(evaluate_le(&zeros, &points[1]), F::zero());
    assert_eq!(evaluate_le(&zeros, &points[2]), F::zero());
}

#[test]
fn test_srs() {
    use ark_bls12_381_04::Bls12_381;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(10, 3, rng);
    let vk = VerifierKey::from(&ck);
    // Make sure that there are enough elements for the entire array.
    assert_eq!(ck.powers_of_g.len(), 11);
    assert_eq!(ck.powers_of_g2, &vk.powers_of_g2[..]);
}

#[test]
fn test_trivial_commitment() {
    use ark_bls12_381_04::Bls12_381;
    use ark_bls12_381_04::Fr;
    use ark_poly_04::univariate::DensePolynomial;
    use ark_poly_04::DenseUVPolynomial;
    use ark_std::One;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(10, 3, rng);
    let vk = VerifierKey::from(&ck);
    let polynomial = DensePolynomial::from_coefficients_slice(&[Fr::zero(), Fr::one(), Fr::one()]);
    let alpha = Fr::zero();

    let commitment = ck.commit(&polynomial);
    let (evaluation, proof) = ck.open(&polynomial, &alpha);
    assert_eq!(evaluation, Fr::zero());
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}

#[test]
fn test_commitment() {
    use ark_bls12_381_04::Bls12_381;
    use ark_bls12_381_04::Fr;
    use ark_poly_04::univariate::DensePolynomial;
    use ark_poly_04::DenseUVPolynomial;
    use ark_poly_04::Polynomial;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(100, 3, rng);
    let vk = VerifierKey::from(&ck);
    let polynomial = DensePolynomial::rand(100, rng);
    let alpha = Fr::zero();

    let commitment = ck.commit(&polynomial);
    let (evaluation, proof) = ck.open(&polynomial, &alpha);
    let expected_evaluation = polynomial.evaluate(&alpha);
    assert_eq!(evaluation, expected_evaluation);
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}

#[test]
fn test_open_multi_points() {
    use ark_std_04::UniformRand;
    use ark_bls12_381_04::{Bls12_381, Fr};
    use ark_poly_04::univariate::DensePolynomial;
    use ark_poly_04::DenseUVPolynomial;
    use ark_std_04::test_rng;

    let max_msm_buffer = 1 << 20;
    let rng = &mut test_rng();
    // f = 80*x^6 + 80*x^5 + 88*x^4 + 3*x^3 + 73*x^2 + 7*x + 24
    let polynomial = [
        Fr::from(80u64),
        Fr::from(80u64),
        Fr::from(88u64),
        Fr::from(3u64),
        Fr::from(73u64),
        Fr::from(7u64),
        Fr::from(24u64),
    ];
    let polynomial_stream = &polynomial[..];
    let beta = Fr::from(53u64);

    let time_ck = CommitterKey::<Bls12_381>::new(200, 3, rng);

    // get a random polynomial with random coefficient,
    let polynomial: Vec<Fr> = DensePolynomial::rand(100, rng).coeffs().to_vec();
    let beta = Fr::rand(rng);
    let evaluation_proof_batch =
        time_ck.open_multi_points(&polynomial_stream, &[beta]);
    let (_, evaluation_proof_single) = time_ck.open(&polynomial_stream, &beta);
    assert_eq!(evaluation_proof_batch, evaluation_proof_single);
}
