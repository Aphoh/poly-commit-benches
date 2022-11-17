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
