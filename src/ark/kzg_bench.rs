use std::marker::PhantomData;

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, One};
use rand::rngs::StdRng;

use crate::PcBench;

use super::kzg::*;

pub type KzgBls12_381Bench = KzgPcBench<Bls12_381>;
pub type KzgBn254Bench = KzgPcBench<Bn254>;

pub struct Setup<UP> {
    params: UP,
    rng: StdRng,
}

pub struct KzgPcBench<E>(PhantomData<E>);

impl<E: Pairing> PcBench for KzgPcBench<E> {
    type Setup = Setup<UniversalParams<E>>;
    type Trimmed = (Powers<E>, VerifierKey<E>);
    type Poly = DensePolynomial<E::ScalarField>;
    type Point = E::ScalarField;
    type Commit = Commitment<E>;
    type Proof = Proof<E>;
    fn setup(max_degree: usize) -> Self::Setup {
        Setup {
            params: <KZG10<E, Self::Poly>>::setup(max_degree, &mut test_rng())
                .expect("Setup works"),
            rng: test_rng(),
        }
    }

    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        <KZG10<E, Self::Poly>>::trim(&s.params, supported_degree).expect("Trim failed")
    }

    fn rand_poly(s: &mut Self::Setup, d: usize) -> (Self::Poly, Self::Point, Self::Point) {
        let poly = DensePolynomial {
            coeffs: (0..=d).map(|_| E::ScalarField::rand(&mut s.rng)).collect(),
        };
        let pt = E::ScalarField::rand(&mut s.rng);
        let eval = poly.evaluate(&pt);
        (poly, pt, eval)
    }

    fn bytes_per_elem() -> usize {
        E::ScalarField::one().serialized_size(ark_serialize::Compress::Yes)
    }

    fn commit(t: &Self::Trimmed, _s: &mut Self::Setup, p: &Self::Poly) -> Self::Commit {
        <KZG10<E, Self::Poly>>::commit(&t.0, &p).expect("Commit failed")
    }

    fn open(
        t: &Self::Trimmed,
        _s: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof {
        <KZG10<E, Self::Poly>>::open(&t.0, &p, *pt).expect("Open failed")
    }

    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool {
        <KZG10<E, Self::Poly>>::check(&t.1, &c, *pt, *value, proof).expect("Check failed")
    }
}
