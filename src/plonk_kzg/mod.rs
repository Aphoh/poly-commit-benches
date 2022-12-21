use crate::PcBench;

use dusk_plonk::{
    commitment_scheme::{
        kzg10::{commitment::Commitment, proof::Proof},
        PublicParameters,
    },
    fft::Polynomial,
    prelude::{BlsScalar, CommitKey, OpeningKey},
};

pub mod enc_bench;

pub struct PlonkKZG;

impl PcBench for PlonkKZG {
    type Setup = (PublicParameters, crate::StdRng);
    type Trimmed = (CommitKey, OpeningKey);
    type Poly = Polynomial;
    type Point = BlsScalar; // This is the i-th root of unity
    type Commit = Commitment;
    type Proof = Commitment;
    fn setup(max_degree: usize) -> Self::Setup {
        let mut rng = crate::test_rng();
        (
            PublicParameters::setup(max_degree, &mut rng).expect("Failed plonk setup"),
            rng,
        )
    }

    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed {
        let trimmed = s.0.trim(supported_degree).expect("Failed to trim");
        trimmed
    }

    fn bytes_per_elem() -> usize {
        32
    }

    fn commit(t: &Self::Trimmed, _s: &mut Self::Setup, p: &Self::Poly) -> Self::Commit {
        t.0.commit(p).unwrap()
    }

    fn open(
        t: &Self::Trimmed,
        _s: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof {
        let witness_poly = t.0.compute_single_witness(&p, &pt);
        t.0.commit(&witness_poly).expect("Failed to compute proof")
    }

    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool {
        t.1.check(
            *pt,
            Proof {
                commitment_to_witness: *proof,
                evaluated_point: *value,
                commitment_to_polynomial: *c,
            },
        )
    }

    fn rand_poly(s: &mut Self::Setup, d: usize) -> (Self::Poly, Self::Point, Self::Point) {
        let pt = Self::Point::random(&mut s.1);
        let poly = Self::Poly::rand(d, &mut s.1);
        let value = poly.evaluate(&pt);
        (poly, pt, value)
    }
}

#[cfg(test)]
mod test {
    use crate::test_works;

    use super::PlonkKZG;

    #[test]
    fn test_it_works() {
        test_works::<PlonkKZG>()
    }
}
