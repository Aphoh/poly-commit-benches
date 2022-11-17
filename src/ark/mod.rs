use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Polynomial, UVPolynomial};
use ark_poly_commit::{LabeledCommitment, PolynomialCommitment, LabeledPolynomial, PCRandomness};
use ark_std::test_rng;
use rand::rngs::StdRng;
use std::marker::PhantomData;

use crate::Bench;

pub mod marlin;
pub type Poly<F> = DensePolynomial<F>;
pub type Trimmed<F, PC> = (
    <PC as PolynomialCommitment<F, Poly<F>>>::CommitterKey,
    <PC as PolynomialCommitment<F, Poly<F>>>::VerifierKey,
);
type Commitment<F, PC> = LabeledCommitment<<PC as PolynomialCommitment<F, Poly<F>>>::Commitment>;

pub struct Setup<UniversalParams> {
    params: UniversalParams,
    rng: StdRng,
}

pub struct ArkBench<F: Field, PC: PolynomialCommitment<F, Poly<F>>>(PhantomData<(F, PC)>);

impl<F: Field, PC: PolynomialCommitment<F, Poly<F>>> Bench for ArkBench<F, PC> {
    type Setup = Setup<PC::UniversalParams>;
    type Trimmed = Trimmed<F, PC>;
    type Poly = Poly<F>;
    type Point = F;
    type Commit = Commitment<F, PC>;
    type Proof = (PC::Proof, Self::Point);

    fn setup(max_degree: usize) -> Self::Setup {
        let mut rng = test_rng();
        let params = PC::setup(max_degree, None, &mut rng).expect("Failed to init bls kzg");

        Setup { params, rng }
    }

    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        PC::trim(&s.params, supported_degree, 0, None).expect("Failed to trim")
    }

    fn rand_poly(s: &mut Self::Setup, d: usize) -> Self::Poly {
        Self::Poly::rand(d, &mut s.rng)
    }

    fn eval_poly(poly: &Self::Poly, pt: &Self::Point) -> Self::Point {
        poly.evaluate(pt)
    }

    fn rand_point(s: &mut Self::Setup) -> Self::Point {
        Self::Point::rand(&mut s.rng)
    }

    fn commit(t: &Self::Trimmed, _s: &mut Self::Setup, p: &Self::Poly) -> Self::Commit {
        let lp = LabeledPolynomial::new("Test".to_string(), p.clone(), None, None);
        let res = PC::commit(&t.0, &[lp], None).expect("Failed to commit");
        res.0[0].clone()
    }

    fn open(
        t: &Self::Trimmed,
        s: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof {
        let lp = LabeledPolynomial::new("Test".to_string(), p.clone(), None, None);
        let opening_challenge = Self::Point::rand(&mut s.rng);

        (
            PC::open(
                &t.0,
                &[lp],
                &[],
                pt,
                opening_challenge,
                &[PC::Randomness::empty()],
                None,
            )
            .expect("Failed to open individial challenge"),
            opening_challenge,
        )
    }

    fn verify(
        t: &Self::Trimmed,
        c: Self::Commit,
        proof: Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool {
        PC::check(&t.1, &[c], pt, [value.clone()], &proof.0, proof.1, None)
            .expect("Proof verification failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_works;

    #[test]
    fn test_bls12_381_marlin() {
        test_works::<marlin::MarlinBls12_381Bench>();
    }

    #[test]
    fn test_bn254_marlin() {
        test_works::<marlin::MarlinBn254Bench>();
    }
}
