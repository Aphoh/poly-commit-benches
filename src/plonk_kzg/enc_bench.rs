use dusk_plonk::{fft::EvaluationDomain, prelude::BlsScalar};
use rand::thread_rng;

use crate::ErasureEncodeBench;

pub struct PlonkEncBench;

impl ErasureEncodeBench for PlonkEncBench {
    type Domain = EvaluationDomain;
    type Point = BlsScalar;

    fn make_domain(size: usize) -> Self::Domain {
        Self::Domain::new(size).unwrap()
    }

    fn rand_points(size: usize) -> Vec<Self::Point> {
        (0..size)
            .map(|_| BlsScalar::random(&mut thread_rng()))
            .collect()
    }

    fn erasure_encode(
        pts: &mut Vec<Self::Point>,
        sub_domain: &Self::Domain,
        big_domain: &Self::Domain,
    ) {
        assert_eq!(sub_domain.size(), pts.len());
        assert_eq!(sub_domain.size() % sub_domain.size(), 0); // Domain a must divide domain b
        sub_domain.ifft_in_place(pts);
        pts.resize(big_domain.size(), BlsScalar::zero());
        *pts = big_domain.fft(pts);
        assert_eq!(pts.len(), big_domain.size());
    }
}

#[cfg(test)]
mod tests {
    use crate::test_enc_works;

    use super::*;
    #[test]
    fn test_works() {
        test_enc_works::<PlonkEncBench>()
    }
}
