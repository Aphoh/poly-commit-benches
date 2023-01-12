use std::marker::PhantomData;

use crate::test_rng;
use ark_ec_04::pairing::Pairing;
use ark_ff_04::One;
use ark_poly_04::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize_04::Compress;
use ark_std_04::UniformRand;

use crate::PcBench;

use super::kzg_multiproof::{method1, method2};

pub struct Multiproof1Bench<E: Pairing, const N_PTS: usize, const N_POLY: usize>(PhantomData<E>);

impl<E: Pairing, const N_PTS: usize, const N_POLY: usize> PcBench
    for Multiproof1Bench<E, N_PTS, N_POLY>
{
    type Setup = ();
    type Trimmed = method1::Setup<E>;
    type Poly = Vec<Vec<E::ScalarField>>;
    type Point = Vec<E::ScalarField>;
    type Eval = Vec<Vec<E::ScalarField>>;
    type Commit = Vec<method1::Commitment<E>>;
    type Proof = (method1::Proof<E>, E::ScalarField);

    fn setup(_max_degree: usize) -> Self::Setup {
        ()
    }

    fn trim(_: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        method1::Setup::<E>::new(supported_degree, N_PTS, &mut test_rng())
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
        p.iter().map(|pi| t.commit(pi).unwrap()).collect()
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
        (t.open(refs.as_ref(), pt, chal).unwrap(), chal)
    }

    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Eval,
        pt: &Self::Point,
    ) -> bool {
        t.verify(c, pt, value, &proof.0, proof.1).unwrap()
    }
}

pub struct Multiproof2Bench<E: Pairing, const N_PTS: usize, const N_POLY: usize>(PhantomData<E>);

impl<E: Pairing, const N_PTS: usize, const N_POLY: usize> PcBench
    for Multiproof2Bench<E, N_PTS, N_POLY>
{
    type Setup = ();
    type Trimmed = method2::Setup<E>;
    type Poly = Vec<Vec<E::ScalarField>>;
    type Point = Vec<E::ScalarField>;
    type Eval = Vec<Vec<E::ScalarField>>;
    type Commit = Vec<method2::Commitment<E>>;
    type Proof = (method2::Proof<E>, E::ScalarField, E::ScalarField);

    fn setup(_max_degree: usize) -> Self::Setup {
        ()
    }

    fn trim(_: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        method2::Setup::<E>::new(supported_degree, N_PTS, &mut test_rng())
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
        p.iter().map(|pi| t.commit(pi).unwrap()).collect()
    }

    fn open(
        t: &Self::Trimmed,
        _: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof {
        let refs: Vec<&Vec<E::ScalarField>> =
            p.iter().map(|poly: &Vec<E::ScalarField>| poly).collect();
        let chal1 = E::ScalarField::rand(&mut test_rng());
        let chal2 = E::ScalarField::rand(&mut test_rng());
        (t.open(refs.as_ref(), pt, chal1, chal2).unwrap(), chal1, chal2)
    }

    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Eval,
        pt: &Self::Point,
    ) -> bool {
        t.verify(c, pt, value, &proof.0, proof.1, proof.2).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_works;
    use ark_bls12_381_04::Bls12_381;

    #[test]
    fn bls12_381_works() {
        test_works::<super::Multiproof1Bench<Bls12_381, 5, 5>>();
        test_works::<super::Multiproof1Bench<Bls12_381, 1, 1>>();
        test_works::<super::Multiproof1Bench<Bls12_381, 1, 5>>();
        test_works::<super::Multiproof1Bench<Bls12_381, 5, 1>>();
        test_works::<super::Multiproof2Bench<Bls12_381, 5, 5>>();
        test_works::<super::Multiproof2Bench<Bls12_381, 1, 1>>();
        test_works::<super::Multiproof2Bench<Bls12_381, 1, 5>>();
        test_works::<super::Multiproof2Bench<Bls12_381, 5, 1>>();
    }
}
