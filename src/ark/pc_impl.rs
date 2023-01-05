use std::marker::PhantomData;

use ark_ff::Field;
use ark_poly::{Polynomial, UVPolynomial, univariate::DensePolynomial};
use ark_poly_commit::{LabeledPolynomial, PCRandomness, PolynomialCommitment, LabeledCommitment};
use rand::rngs::StdRng;

use crate::PcBench;

pub struct Setup<UniversalParams> {
    params: UniversalParams,
    rng: StdRng,
}

pub type Poly<F> = DensePolynomial<F>;
pub type Trimmed<F, PC> = (
    <PC as PolynomialCommitment<F, Poly<F>>>::CommitterKey,
    <PC as PolynomialCommitment<F, Poly<F>>>::VerifierKey,
);
type Commitment<F, PC> = LabeledCommitment<<PC as PolynomialCommitment<F, Poly<F>>>::Commitment>;

pub struct ArkPcBench<F: Field, PC: PolynomialCommitment<F, Poly<F>>>(PhantomData<(F, PC)>);

impl<F: Field, PC: PolynomialCommitment<F, Poly<F>>> PcBench for ArkPcBench<F, PC> {
    type Setup = Setup<PC::UniversalParams>;
    type Trimmed = Trimmed<F, PC>;
    type Poly = Poly<F>;
    type Point = F;
    type Commit = Commitment<F, PC>;
    type Proof = (PC::Proof, Self::Point);

    fn setup(max_degree: usize) -> Self::Setup {
        let mut rng = crate::test_rng();
        let params = PC::setup(max_degree, None, &mut rng).expect("Failed to init bls kzg");

        Setup { params, rng }
    }

    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        PC::trim(&s.params, supported_degree, 0, None).expect("Failed to trim")
    }

    fn rand_poly(s: &mut Self::Setup, d: usize) -> (Self::Poly, Self::Point, Self::Point) {
        let poly = Self::Poly::rand(d, &mut s.rng);
        let pt = Self::Point::rand(&mut s.rng);
        let value = poly.evaluate(&pt);
        (poly, pt, value)
    }

    fn bytes_per_elem() -> usize {
        F::one().serialized_size() - 1 // Trim one byte for keeping in modspace
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
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool {
        PC::check(
            &t.1,
            &[c.clone()],
            pt,
            [value.clone()],
            &proof.0,
            proof.1,
            None,
        )
        .expect("Proof verification failed")
    }
}
