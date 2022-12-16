use crate::{Bench, ErasureEncodeBench};

use dusk_plonk::{
    commitment_scheme::{
        kzg10::{commitment::Commitment, proof::Proof},
        PublicParameters,
    },
    fft::{EvaluationDomain, Polynomial},
    prelude::{BlsScalar, CommitKey, OpeningKey},
};
use rand::thread_rng;
pub struct PlonkKZG;

impl ErasureEncodeBench for PlonkKZG {
    type Domain = EvaluationDomain;
    type Points = Vec<BlsScalar>;

    fn make_domain(size: usize) -> Self::Domain {
        EvaluationDomain::new(size).expect("Failed to make evaluation domain")
    }

    fn rand_points(size: usize) -> Self::Points {
        (0..size)
            .map(|_| BlsScalar::random(&mut thread_rng()))
            .collect()
    }

    fn erasure_encode(
        pts: &mut Self::Points,
        sub_domain: &Self::Domain,
        big_domain: &Self::Domain,
    ) {
        assert_eq!(sub_domain.size(), pts.len());
        assert_eq!(big_domain.size() % sub_domain.size(), 0);
        sub_domain.ifft_in_place(pts);
        pts.resize(big_domain.size(), BlsScalar::zero());
        // Annoyingly, fft in place is not exposed...
        let res = big_domain.fft(&pts);
        pts.copy_from_slice(&res);
    }
}

impl Bench for PlonkKZG {
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
