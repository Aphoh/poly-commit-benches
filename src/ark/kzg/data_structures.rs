use std::collections::BTreeMap;

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, ToBytes, ToConstraintField, Zero, Field};
use ark_poly_commit::{PCUniversalParams, PCCommitment, PCProof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    borrow::Cow,
    io::{Read, Write},
    ops::AddAssign,
};

#[derive(Clone, Debug)]
pub struct UniversalParams<E: PairingEngine> {
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

impl<E: PairingEngine> PCUniversalParams for UniversalParams<E> {
    fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

impl<E: PairingEngine> CanonicalSerialize for UniversalParams<E> {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.powers_of_g.serialize(&mut writer)?;
        self.powers_of_gamma_g.serialize(&mut writer)?;
        self.h.serialize(&mut writer)?;
        self.beta_h.serialize(&mut writer)
    }

    fn serialized_size(&self) -> usize {
        self.powers_of_g.serialized_size()
            + self.powers_of_gamma_g.serialized_size()
            + self.h.serialized_size()
            + self.beta_h.serialized_size()
    }

    fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.powers_of_g.serialize_unchecked(&mut writer)?;
        self.powers_of_gamma_g.serialize_unchecked(&mut writer)?;
        self.h.serialize_unchecked(&mut writer)?;
        self.beta_h.serialize_unchecked(&mut writer)
    }

    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.powers_of_g.serialize_uncompressed(&mut writer)?;
        self.powers_of_gamma_g.serialize_uncompressed(&mut writer)?;
        self.h.serialize_uncompressed(&mut writer)?;
        self.beta_h.serialize_uncompressed(&mut writer)
    }

    fn uncompressed_size(&self) -> usize {
        self.powers_of_g.uncompressed_size()
            + self.powers_of_gamma_g.uncompressed_size()
            + self.h.uncompressed_size()
            + self.beta_h.uncompressed_size()
    }
}

impl<E: PairingEngine> CanonicalDeserialize for UniversalParams<E> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let powers_of_g = Vec::<E::G1Affine>::deserialize(&mut reader)?;
        let powers_of_gamma_g = BTreeMap::<usize, E::G1Affine>::deserialize(&mut reader)?;
        let h = E::G2Affine::deserialize(&mut reader)?;
        let beta_h = E::G2Affine::deserialize(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }

    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let powers_of_g = Vec::<E::G1Affine>::deserialize_uncompressed(&mut reader)?;
        let powers_of_gamma_g =
            BTreeMap::<usize, E::G1Affine>::deserialize_uncompressed(&mut reader)?;
        let h = E::G2Affine::deserialize_uncompressed(&mut reader)?;
        let beta_h = E::G2Affine::deserialize_uncompressed(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let powers_of_g = Vec::<E::G1Affine>::deserialize_unchecked(&mut reader)?;
        let powers_of_gamma_g = BTreeMap::<usize, E::G1Affine>::deserialize_unchecked(&mut reader)?;
        let h = E::G2Affine::deserialize_unchecked(&mut reader)?;
        let beta_h = E::G2Affine::deserialize_unchecked(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }
}

/// `Powers` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Clone, Debug)]
pub struct Powers<'a, E: PairingEngine> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub powers_of_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_gamma_g: Cow<'a, [E::G1Affine]>,
}

impl<E: PairingEngine> Powers<'_, E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Clone, Debug)]
pub struct VerifierKey<E: PairingEngine> {
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

impl<E: PairingEngine> CanonicalSerialize for VerifierKey<E> {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.g.serialize(&mut writer)?;
        self.gamma_g.serialize(&mut writer)?;
        self.h.serialize(&mut writer)?;
        self.beta_h.serialize(&mut writer)
    }

    fn serialized_size(&self) -> usize {
        self.g.serialized_size()
            + self.gamma_g.serialized_size()
            + self.h.serialized_size()
            + self.beta_h.serialized_size()
    }

    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.g.serialize_uncompressed(&mut writer)?;
        self.gamma_g.serialize_uncompressed(&mut writer)?;
        self.h.serialize_uncompressed(&mut writer)?;
        self.beta_h.serialize_uncompressed(&mut writer)
    }

    fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.g.serialize_unchecked(&mut writer)?;
        self.gamma_g.serialize_unchecked(&mut writer)?;
        self.h.serialize_unchecked(&mut writer)?;
        self.beta_h.serialize_unchecked(&mut writer)
    }

    fn uncompressed_size(&self) -> usize {
        self.g.uncompressed_size()
            + self.gamma_g.uncompressed_size()
            + self.h.uncompressed_size()
            + self.beta_h.uncompressed_size()
    }
}

impl<E: PairingEngine> CanonicalDeserialize for VerifierKey<E> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let g = E::G1Affine::deserialize(&mut reader)?;
        let gamma_g = E::G1Affine::deserialize(&mut reader)?;
        let h = E::G2Affine::deserialize(&mut reader)?;
        let beta_h = E::G2Affine::deserialize(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }

    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let g = E::G1Affine::deserialize_uncompressed(&mut reader)?;
        let gamma_g = E::G1Affine::deserialize_uncompressed(&mut reader)?;
        let h = E::G2Affine::deserialize_uncompressed(&mut reader)?;
        let beta_h = E::G2Affine::deserialize_uncompressed(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let g = E::G1Affine::deserialize_unchecked(&mut reader)?;
        let gamma_g = E::G1Affine::deserialize_unchecked(&mut reader)?;
        let h = E::G2Affine::deserialize_unchecked(&mut reader)?;
        let beta_h = E::G2Affine::deserialize_unchecked(&mut reader)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        })
    }
}

impl<E: PairingEngine> ToBytes for VerifierKey<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> ark_std::io::Result<()> {
        self.g.write(&mut writer)?;
        self.gamma_g.write(&mut writer)?;
        self.h.write(&mut writer)?;
        self.beta_h.write(&mut writer)?;
        self.prepared_h.write(&mut writer)?;
        self.prepared_beta_h.write(&mut writer)
    }
}

impl<E: PairingEngine> ToConstraintField<<E::Fq as Field>::BasePrimeField> for VerifierKey<E>
where
    E::G1Affine: ToConstraintField<<E::Fq as Field>::BasePrimeField>,
    E::G2Affine: ToConstraintField<<E::Fq as Field>::BasePrimeField>,
{
    fn to_field_elements(&self) -> Option<Vec<<E::Fq as Field>::BasePrimeField>> {
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
#[derive(Clone, Debug)]
pub struct PreparedVerifierKey<E: PairingEngine> {
    /// The generator of G1, prepared for power series.
    pub prepared_g: Vec<E::G1Affine>,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: PairingEngine> PreparedVerifierKey<E> {
    /// prepare `PreparedVerifierKey` from `VerifierKey`
    pub fn prepare(vk: &VerifierKey<E>) -> Self {
        let supported_bits = E::Fr::size_in_bits();

        let mut prepared_g = Vec::<E::G1Affine>::new();
        let mut g = E::G1Projective::from(vk.g.clone());
        for _ in 0..supported_bits {
            prepared_g.push(g.clone().into());
            g.double_in_place();
        }

        Self {
            prepared_g,
            prepared_h: vk.prepared_h.clone(),
            prepared_beta_h: vk.prepared_beta_h.clone(),
        }
    }
}

/// `Commitment` commits to a polynomial. It is output by `KZG10::commit`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct Commitment<E: PairingEngine>(
    /// The commitment is a group element.
    pub E::G1Affine,
);

impl<E: PairingEngine> ToBytes for Commitment<E> {
    #[inline]
    fn write<W: Write>(&self, writer: W) -> ark_std::io::Result<()> {
        self.0.write(writer)
    }
}

impl<E: PairingEngine> PCCommitment for Commitment<E> {
    #[inline]
    fn empty() -> Self {
        Commitment(E::G1Affine::zero())
    }

    fn has_degree_bound(&self) -> bool {
        false
    }

    fn size_in_bytes(&self) -> usize {
        ark_ff::to_bytes![E::G1Affine::zero()].unwrap().len() / 2
    }
}

impl<E: PairingEngine> ToConstraintField<<E::Fq as Field>::BasePrimeField> for Commitment<E>
where
    E::G1Affine: ToConstraintField<<E::Fq as Field>::BasePrimeField>,
{
    fn to_field_elements(&self) -> Option<Vec<<E::Fq as Field>::BasePrimeField>> {
        self.0.to_field_elements()
    }
}

impl<'a, E: PairingEngine> AddAssign<(E::Fr, &'a Commitment<E>)> for Commitment<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::Fr, &'a Commitment<E>)) {
        let mut other = other.0.mul(f.into_repr());
        other.add_assign_mixed(&self.0);
        self.0 = other.into();
    }
}

/// `PreparedCommitment` commits to a polynomial and prepares for mul_bits.
pub struct PreparedCommitment<E: PairingEngine>(
    /// The commitment is a group element.
    pub Vec<E::G1Affine>,
);

impl<E: PairingEngine> PreparedCommitment<E> {
    /// prepare `PreparedCommitment` from `Commitment`
    pub fn prepare(comm: &Commitment<E>) -> Self {
        let mut prepared_comm = Vec::<E::G1Affine>::new();
        let mut cur = E::G1Projective::from(comm.0.clone());

        let supported_bits = E::Fr::size_in_bits();

        for _ in 0..supported_bits {
            prepared_comm.push(cur.clone().into());
            cur.double_in_place();
        }

        Self { 0: prepared_comm }
    }
}


/// `Proof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<E: PairingEngine> {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: E::G1Affine,
}

impl<E: PairingEngine> PCProof for Proof<E> {
    fn size_in_bytes(&self) -> usize {
        ark_ff::to_bytes![E::G1Affine::zero()].unwrap().len() / 2
    }
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> ark_std::io::Result<()> {
        self.w.write(&mut writer)
    }
}
