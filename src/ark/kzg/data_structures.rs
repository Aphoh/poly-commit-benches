use std::collections::BTreeMap;

use ark_ec::{Group, pairing::Pairing, AffineRepr};
use ark_ff::{Field, ToConstraintField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_std::ops::AddAssign;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniversalParams<E: Pairing> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// Group elements of the form `{ \beta^i \gamma G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_gamma_g: BTreeMap<usize, E::G1Affine>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: Pairing> UniversalParams<E> {
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

/// `Powers` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Clone, Debug)]
pub struct Powers<E: Pairing> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_gamma_g: Vec<E::G1Affine>,
}

impl<E: Pairing> Powers<E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct VerifierKey<E: Pairing> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: Pairing> ToConstraintField<<E::BaseField as Field>::BasePrimeField> for VerifierKey<E>
where
    E::G1Affine: ToConstraintField<<E::BaseField as Field>::BasePrimeField>,
    E::G2Affine: ToConstraintField<<E::BaseField as Field>::BasePrimeField>,
{
    fn to_field_elements(&self) -> Option<Vec<<E::BaseField as Field>::BasePrimeField>> {
        let mut res = Vec::new();

        res.extend_from_slice(&self.g.to_field_elements().unwrap());
        res.extend_from_slice(&self.gamma_g.to_field_elements().unwrap());
        res.extend_from_slice(&self.h.to_field_elements().unwrap());
        res.extend_from_slice(&self.beta_h.to_field_elements().unwrap());

        Some(res)
    }
}

/// `PreparedVerifierKey` is the fully prepared version for checking evaluation proofs for a given commitment.
/// We omit gamma here for simplicity.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifierKey<E: Pairing> {
    /// The generator of G1, prepared for power series.
    pub prepared_g: Vec<E::G1Affine>,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

/// `Commitment` commits to a polynomial. It is output by `KZG10::commit`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct Commitment<E: Pairing>(
    /// The commitment is a group element.
    pub E::G1Affine,
);

impl<E: Pairing> Commitment<E> {
    #[inline]
    pub fn empty() -> Self {
        Commitment(E::G1Affine::zero())
    }

    pub fn has_degree_bound(&self) -> bool {
        false
    }

    pub fn size_in_bytes(&self) -> usize {
        self.0.serialized_size(Compress::Yes)
    }
}

impl<E: Pairing> ToConstraintField<<E::BaseField as Field>::BasePrimeField> for Commitment<E>
where
    E::G1Affine: ToConstraintField<<E::BaseField as Field>::BasePrimeField>,
{
    fn to_field_elements(&self) -> Option<Vec<<E::BaseField as Field>::BasePrimeField>> {
        self.0.to_field_elements()
    }
}

impl<'a, E: Pairing> AddAssign<(E::ScalarField, &'a Commitment<E>)> for Commitment<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::ScalarField, &'a Commitment<E>)) {
        let mut other = other.0 * f;
        other += &self.0;
        self.0 = other.into();
    }
}

/// `PreparedCommitment` commits to a polynomial and prepares for mul_bits.
pub struct PreparedCommitment<E: Pairing>(
    /// The commitment is a group element.
    pub Vec<E::G1Affine>,
);

impl<E: Pairing> PreparedCommitment<E> {
    /// prepare `PreparedCommitment` from `Commitment`
    pub fn prepare(comm: &Commitment<E>) -> Self {
        let mut prepared_comm = Vec::<E::G1Affine>::new();
        let mut cur = E::G1::from(comm.0.clone());

        let supported_bits = E::ScalarField::MODULUS_BIT_SIZE;

        for _ in 0..supported_bits {
            prepared_comm.push(cur.clone().into());
            cur.double_in_place();
        }

        Self { 0: prepared_comm }
    }
}

/// `Proof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<E: Pairing> {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: E::G1Affine,
}

impl<E: Pairing> Proof<E> {
    pub fn size_in_bytes(&self) -> usize {
        self.w.serialized_size(Compress::Yes)
    }
}
