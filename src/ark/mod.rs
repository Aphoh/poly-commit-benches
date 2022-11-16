use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{marlin_pc::MarlinKZG10, LabeledCommitment, PolynomialCommitment};

pub mod marlin;
type FieldFor<E> = <E as PairingEngine>::Fr;
type Poly<E> = DensePolynomial<FieldFor<E>>;
type KZG<E> = MarlinKZG10<E, Poly<E>>;
type Trimmed<E> = (
    <KZG<E> as PolynomialCommitment<FieldFor<E>, Poly<E>>>::CommitterKey,
    <KZG<E> as PolynomialCommitment<FieldFor<E>, Poly<E>>>::VerifierKey,
);
type Commitment<E> =
    LabeledCommitment<<KZG<E> as PolynomialCommitment<FieldFor<E>, Poly<E>>>::Commitment>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_works;

    #[test]
    fn test_bls12_381_marlin() {
        test_works::<marlin::MarlinBench<ark_bls12_381::Bls12_381>>();
    }

    #[test]
    fn test_bn254_marlin() {
        test_works::<marlin::MarlinBench<ark_bn254::Bn254>>();
    }
}
