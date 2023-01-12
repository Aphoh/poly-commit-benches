use std::marker::PhantomData;

use ark_ec_04::pairing::Pairing;
use ark_ff_04::One;
use ark_poly_04::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize_04::Compress;
use ark_std_04::{test_rng, UniformRand};

use crate::PcBench;

use super::streaming_kzg::{Commitment, CommitterKey, EvaluationProof, VerifierKey};

pub struct StreamingKzgBench<E: Pairing, const N_PTS: usize, const N_POLY: usize>(PhantomData<E>);

pub struct Setup<E: Pairing> {
    ck: CommitterKey<E>,
    vk: VerifierKey<E>,
}

impl<E: Pairing, const N_PTS: usize, const N_POLY: usize> PcBench
    for StreamingKzgBench<E, N_PTS, N_POLY>
{
    type Setup = ();
    type Trimmed = Setup<E>;
    type Poly = Vec<Vec<E::ScalarField>>;
    type Point = Vec<E::ScalarField>;
    type Eval = Vec<Vec<E::ScalarField>>;
    type Commit = Vec<Commitment<E>>;
    type Proof = (EvaluationProof<E>, E::ScalarField);

    fn setup(_max_degree: usize) -> Self::Setup {
        ()
    }

    fn trim(_: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        let ck = CommitterKey::<E>::new(supported_degree, N_PTS, &mut test_rng());
        let vk = VerifierKey::from(&ck);
        Self::Trimmed { ck, vk }
    }

    fn rand_poly(_: &mut Self::Setup, d: usize) -> (Self::Poly, Self::Point, Self::Eval) {
        let mut rng = test_rng();
        let polys = (0..N_POLY)
            .map(|_| DensePolynomial::<E::ScalarField>::rand(d, &mut rng))
            .collect::<Vec<_>>();
        let open_pts: Self::Point = (0..N_PTS).map(|_| E::ScalarField::rand(&mut rng)).collect();
        let evals = polys
            .iter()
            .map(|p| open_pts.iter().map(|e| p.evaluate(e)).collect::<Vec<_>>())
            .collect::<Self::Eval>();
        (
            polys.into_iter().map(|p| p.coeffs).collect(),
            open_pts,
            evals,
        )
    }

    fn bytes_per_elem() -> usize {
        use ark_serialize_04::CanonicalSerialize;
        (E::ScalarField::one().serialized_size(Compress::Yes) - 1) * N_PTS * N_POLY
    }

    fn commit(t: &Self::Trimmed, _: &mut Self::Setup, p: &Self::Poly) -> Self::Commit {
        t.ck.batch_commit(p)
    }

    fn open(
        t: &Self::Trimmed,
        _: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof {
        let refs: Vec<&Vec<E::ScalarField>> =
            p.iter().map(|poly: &Vec<E::ScalarField>| poly).collect();
        let chal = E::ScalarField::rand(&mut test_rng());
        (t.ck.batch_open_multi_points(refs.as_ref(), pt, &chal), chal)
    }

    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Eval,
        pt: &Self::Point,
    ) -> bool {
        t.vk.verify_multi_points(c, pt, value, &proof.0, &proof.1)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_works;
    use ark_bls12_381_04::Bls12_381;

    #[test]
    fn bls12_381_works() {
        test_works::<super::StreamingKzgBench<Bls12_381, 5, 5>>();
        test_works::<super::StreamingKzgBench<Bls12_381, 1, 1>>();
        test_works::<super::StreamingKzgBench<Bls12_381, 1, 5>>();
        test_works::<super::StreamingKzgBench<Bls12_381, 5, 1>>();
    }
}
