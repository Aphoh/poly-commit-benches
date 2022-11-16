use ark_ff::{Field, UniformRand};
use ark_poly::{Polynomial, UVPolynomial};
use ark_poly_commit::{
    kzg10::Proof,
    marlin_pc::{Randomness, UniversalParams},
    LabeledPolynomial, PCRandomness, PolynomialCommitment,
};
use ark_std::test_rng;
use rand::rngs::StdRng;
use std::marker::PhantomData;

use crate::Bench;

use super::*;

pub struct MarlinBench<E: PairingEngine>(PhantomData<E>);

impl<E: PairingEngine> Bench for MarlinBench<E> {
    type Setup = Setup<E>;
    type Trimmed = Trimmed<E>;
    type Poly = Poly<E>;
    type Point = FieldFor<E>;
    type Commit = Commitment<E>;
    type Proof = (Proof<E>, Self::Point);

    fn setup(max_degree: usize) -> Self::Setup {
        let mut rng = test_rng();
        let params = KZG::setup(max_degree, None, &mut rng).expect("Failed to init bls kzg");

        Setup { params, rng }
    }

    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        KZG::trim(&s.params, supported_degree, 0, None).expect("Failed to trim")
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
        let res = KZG::commit(&t.0, &[lp], None).expect("Failed to commit");
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
        let opening_challenges = |pow| opening_challenge.pow(&[pow]);

        (
            KZG::open_individual_opening_challenges(
                &t.0,
                &[lp],
                &[],
                pt,
                &opening_challenges,
                &[Randomness::empty()],
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
        let opening_challenges = |pow| proof.1.pow(&[pow]);
        KZG::check_individual_opening_challenges(
            &t.1,
            &[c],
            pt,
            [value.clone()],
            &proof.0,
            &opening_challenges,
            None,
        )
        .expect("Proof verification failed")
    }
}

pub struct Setup<E: PairingEngine> {
    params: UniversalParams<E>,
    rng: StdRng,
}
