//! An impementation of a time-efficient version of Kate et al's polynomial commitment,
//! with optimization from [\[BDFG20\]](https://eprint.iacr.org/2020/081.pdf).
use ark_ec_04::pairing::Pairing;
use ark_ec_04::scalar_mul::fixed_base::FixedBase;
use ark_ec_04::{AffineRepr, CurveGroup};
use ark_ff_04::UniformRand;
use ark_ff_04::{PrimeField, Zero};
use ark_poly_04::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std_04::borrow::Borrow;
use ark_std_04::ops::{Div, Mul};
use ark_std_04::rand::RngCore;
use ark_std_04::vec::Vec;
use ark_std_04::{end_timer, start_timer};

use crate::ark::streaming_kzg::{
    linear_combination, msm, powers, Commitment, EvaluationProof, VerifierKey,
};

use super::vanishing_polynomial;

/// The SRS for the polynomial commitment scheme for a max
///
/// The SRS consists of the `max_degree` powers of \\(\tau\\) in \\(\GG_1\\)
/// plus the `max_eval_degree` powers over \\(\GG_2\\),
/// where `max_degree` is the max polynomial degree to commit to,
/// and `max_eval_degree` is the max number of different points to open simultaneously.
pub struct CommitterKey<E: Pairing> {
    pub(crate) powers_of_g: Vec<E::G1Affine>,
    pub(crate) powers_of_g2: Vec<E::G2Affine>,
}

impl<E: Pairing> From<&CommitterKey<E>> for VerifierKey<E> {
    fn from(ck: &CommitterKey<E>) -> VerifierKey<E> {
        let max_eval_points = ck.max_eval_points();
        let powers_of_g2 = ck.powers_of_g2[..max_eval_points + 1].to_vec();
        let powers_of_g = ck.powers_of_g[..max_eval_points].to_vec();

        VerifierKey {
            powers_of_g,
            powers_of_g2,
        }
    }
}

impl<E: Pairing> CommitterKey<E> {
    /// The setup algorithm for the commitment scheme.
    ///
    /// Given a degree bound `max_degree`,
    /// an evaluation point bound `max_eval_points`,
    /// and a cryptographically-secure random number generator `rng`,
    /// construct the committer key.
    pub fn new(max_degree: usize, max_eval_points: usize, rng: &mut impl RngCore) -> Self {
        // Compute the consecutive powers of an element.
        let tau = E::ScalarField::rand(rng);
        let powers_of_tau = powers(tau, max_degree + 1);

        let g = E::G1::rand(rng);
        let window_size = FixedBase::get_mul_window_size(max_degree + 1);
        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
        let g_table: Vec<Vec<E::G1Affine>> =
            FixedBase::get_window_table(scalar_bits, window_size, g);
        let powers_of_g_proj =
            FixedBase::msm(scalar_bits, window_size, &g_table, powers_of_tau.as_ref());
        let powers_of_g = E::G1::normalize_batch(&powers_of_g_proj);

        let g2 = E::G2::rand(rng).into_affine();
        let powers_of_g2 = powers_of_tau
            .iter()
            .take(max_eval_points + 1)
            .map(|t| g2.mul(t).into_affine())
            .collect::<Vec<_>>();

        CommitterKey {
            powers_of_g,
            powers_of_g2,
        }
    }

    /// Return the bound on evaluation points.
    #[inline]
    pub fn max_eval_points(&self) -> usize {
        self.powers_of_g2.len() - 1
    }

    /// Given a polynomial `polynomial` of degree less than `max_degree`, return a commitment to `polynomial`.
    pub fn commit(&self, polynomial: &[E::ScalarField]) -> Commitment<E> {
        Commitment(msm::<E>(&self.powers_of_g, polynomial))
    }

    /// Obtain a new preprocessed committer key defined by the indices `indices`.
    pub fn index_by(&self, indices: &[usize]) -> Self {
        let mut indexed_powers_of_g = vec![E::G1Affine::zero(); self.powers_of_g.len()];
        indices
            .iter()
            .zip(self.powers_of_g.iter())
            .for_each(|(&i, &g)| {
                let proj: E::G1 = indexed_powers_of_g[i].into();
                indexed_powers_of_g[i] = (proj + g).into()
            });
        Self {
            powers_of_g2: self.powers_of_g2.clone(),
            powers_of_g: indexed_powers_of_g,
        }
    }

    /// Given an iterator over `polynomials`, expressed as vectors of coefficients, return a vector of commitmetns to all of them.
    pub fn batch_commit<J>(&self, polynomials: J) -> Vec<Commitment<E>>
    where
        J: IntoIterator,
        J::Item: Borrow<Vec<E::ScalarField>>,
    {
        polynomials
            .into_iter()
            .map(|p| self.commit(p.borrow()))
            .collect::<Vec<_>>()
    }

    /// Given a polynomial `polynomial` and an evaluation point `evaluation_point`,
    /// return the evaluation of `polynomial in `evaluation_point`,
    /// together with an evaluation proof.
    pub fn open(
        &self,
        polynomial: &[E::ScalarField],
        evalualtion_point: &E::ScalarField,
    ) -> (E::ScalarField, EvaluationProof<E>) {
        let mut quotient = Vec::new();

        let mut previous = E::ScalarField::zero();
        for &c in polynomial.iter().rev() {
            let coefficient = c + previous * evalualtion_point;
            quotient.insert(0, coefficient);
            previous = coefficient;
        }

        let (&evaluation, quotient) = quotient
            .split_first()
            .unwrap_or((&E::ScalarField::zero(), &[]));
        let evaluation_proof = msm::<E>(&self.powers_of_g, quotient);
        (evaluation, EvaluationProof(evaluation_proof))
    }

    /// Evaluate a single polynomial at a set of points `eval_points`, and provide a single evaluation proof.
    pub fn open_multi_points(
        &self,
        polynomial: &[E::ScalarField],
        eval_points: &[E::ScalarField],
    ) -> EvaluationProof<E> {
        // Computing the vanishing polynomial over eval_points
        let t0 = start_timer!(|| "vanishing poly");
        let z_poly = vanishing_polynomial(eval_points);
        end_timer!(t0);

        let t1 = start_timer!(|| "Poly division");
        let f_poly = DensePolynomial::from_coefficients_slice(polynomial);
        let q_poly = f_poly.div(&z_poly);
        end_timer!(t1);

        let t2 = start_timer!(|| "Eval proof");
        let res = EvaluationProof(self.commit(&q_poly.coeffs).0);
        end_timer!(t2);
        res
    }

    /// Evaluate a set of polynomials at a set of points `eval_points`, and provide a single batched evaluation proof.
    /// `eval_chal` is the random challenge for batching evaluation proofs across different polynomials.
    pub fn batch_open_multi_points(
        &self,
        polynomials: &[&Vec<E::ScalarField>],
        eval_points: &[E::ScalarField],
        eval_chal: &E::ScalarField,
    ) -> EvaluationProof<E> {
        let t0 = start_timer!(|| "batch open multi points");
        assert!(eval_points.len() < self.powers_of_g2.len());

        let t1 = start_timer!(|| "powers");
        let etas = powers(*eval_chal, polynomials.len());
        end_timer!(t1);

        let t2 = start_timer!(|| "batched poly");
        let batched_polynomial =
            linear_combination(polynomials, &etas).unwrap_or_else(|| vec![E::ScalarField::zero()]);
        end_timer!(t2);

        let t3 = start_timer!(|| "open multi points");
        let res = self.open_multi_points(&batched_polynomial, eval_points);
        end_timer!(t3);

        end_timer!(t0);
        res
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381_04::Fr;
    use ark_poly_04::polynomial::univariate::DenseOrSparsePolynomial;
    use ark_poly_04::Polynomial;
    use crate::test_rng;

    use super::*;
    #[test]
    fn test_single_remainder_sanity() {
        let poly = DensePolynomial::<Fr>::rand(50, &mut test_rng());
        let pts = (0..10)
            .map(|_| Fr::rand(&mut test_rng()))
            .collect::<Vec<_>>();
        let vp = vanishing_polynomial(&pts);
        for p in &pts {
            assert_eq!(vp.evaluate(&p), Fr::zero());
        }

        let (_, rem) = pdiv(&poly, &vp);
        for p in &pts {
            assert_eq!(rem.evaluate(&p), poly.evaluate(&p));
        }
    }

    fn pdiv(
        f: &DensePolynomial<Fr>,
        other: &DensePolynomial<Fr>,
    ) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
        let f = DenseOrSparsePolynomial::from(f);
        let other = DenseOrSparsePolynomial::from(other);
        f.divide_with_q_and_r(&other).expect("Div failed")
    }

    #[test]
    fn test_sum_remainder_sanity() {
        let polys = (0..5)
            .map(|_| DensePolynomial::<Fr>::rand(50, &mut test_rng()).coeffs)
            .collect::<Vec<Vec<Fr>>>();
        let pts = (0..10)
            .map(|_| Fr::rand(&mut test_rng()))
            .collect::<Vec<_>>();
        let chal = Fr::rand(&mut test_rng());
        let powers = powers(chal, polys.len());

        // Compute the remainders just by doing some aggregate math
        let vp = vanishing_polynomial(&pts);
        let agg_poly =
            DensePolynomial::from_coefficients_vec(linear_combination(&polys, &powers).unwrap());

        let (_, agg_rem) = pdiv(&agg_poly, &vp);

        // Now compute each of the remainders separately and aggregate
        let mut rems = Vec::new();
        for p in polys {
            let (_, remi) = pdiv(&DensePolynomial::from_coefficients_vec(p), &vp);
            rems.push(remi.coeffs);
        }
        let rems_poly = linear_combination(&rems, &powers).unwrap();

        assert_eq!(rems_poly, agg_rem.coeffs);
    }
}
