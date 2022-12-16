use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_poly_commit::marlin_pc::MarlinKZG10;

use super::*;

type PolyOf<E> = Poly<<E as PairingEngine>::Fr>;
type MarlinBenchFor<E> = ArkBench<<E as PairingEngine>::Fr, MarlinKZG10<E, PolyOf<E>>>;

pub type MarlinBls12_381Bench = MarlinBenchFor<Bls12_381>;
pub type MarlinBls12_377Bench = MarlinBenchFor<Bls12_377>;
pub type MarlinBn254Bench = MarlinBenchFor<Bn254>;

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::{UniformRand, Zero};
    use rand::thread_rng;

    #[test]
    fn test_can_fft() {
        type Fr = <Bls12_381 as PairingEngine>::Fr;
        let size: usize = 32;
        let domain = <Radix2EvaluationDomain<Fr>>::new(size).unwrap();
        let mut pts = vec![];
        for _ in 0..size {
            pts.push(Fr::rand(&mut thread_rng()));
        }
        pts.resize(domain.size(), Fr::zero());
        let fftd = domain.fft(&pts);
        let ifftd = domain.ifft(&fftd);
        assert_eq!(pts, ifftd);
    }
}
