use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::PairingEngine;
use ark_poly_commit::marlin_pc::MarlinKZG10;

use super::pc_impl::{ArkPcBench, Poly};

type PolyOf<E> = Poly<<E as PairingEngine>::Fr>;
type MarlinBenchFor<E> = ArkPcBench<<E as PairingEngine>::Fr, MarlinKZG10<E, PolyOf<E>>>;

pub type MarlinBls12_381Bench = MarlinBenchFor<Bls12_381>;
pub type MarlinBls12_377Bench = MarlinBenchFor<Bls12_377>;
pub type MarlinBn254Bench = MarlinBenchFor<Bn254>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_works, PcBench};

    #[test]
    fn test_bls12_381_marlin() {
        test_works::<MarlinBls12_381Bench>();
    }

    #[test]
    fn test_bn254_marlin() {
        test_works::<MarlinBn254Bench>();
    }

    #[test]
    fn test_bls12_381_ser_size() {
        assert_eq!(MarlinBls12_381Bench::bytes_per_elem(), 32);
    }

    #[test]
    fn test_bn254_ser_size() {
        assert_eq!(MarlinBn254Bench::bytes_per_elem(), 32);
    }
}
