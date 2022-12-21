//! Here we construct a polynomial commitment that enables users to commit to a
//! single polynomial `p`, and then later provide an evaluation proof that
//! convinces verifiers that a claimed value `v` is the true evaluation of `p`
//! at a chosen point `x`. Our construction follows the template of the construction
//! proposed by Kate, Zaverucha, and Goldberg ([KZG11](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf)).
//! This construction achieves extractability in the algebraic group model (AGM).
use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::UVPolynomial;
use ark_poly_commit::LabeledPolynomial;
use ark_std::{marker::PhantomData, ops::Div, vec};

use ark_std::rand::RngCore;

mod data_structures;
pub use data_structures::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Degree is zero")]
    DegreeIsZero,
    #[error("Degree is zero")]
    UnsupportedDegreeBound(usize),
    #[error("Degree is zero")]
    IncorrectDegreeBound {
        poly_degree: usize,
        degree_bound: usize,
        supported_degree: usize,
        label: String,
    },
    #[error("Degree is zero")]
    TooManyCoefficients {
        num_coefficients: usize,
        num_powers: usize,
    },
}

/// `KZG10` is an implementation of the polynomial commitment scheme of
/// [Kate, Zaverucha and Goldbgerg][kzg10]
///
/// [kzg10]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
pub struct KZG10<E: PairingEngine, P: UVPolynomial<E::Fr>> {
    _engine: PhantomData<E>,
    _poly: PhantomData<P>,
}

impl<E, P> KZG10<E, P>
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    /// Constructs public parameters when given as input the maximum degree `degree`
    /// for the polynomial commitment scheme.
    pub fn setup<R: RngCore>(
        max_degree: usize,
        produce_g2_powers: bool,
        rng: &mut R,
    ) -> Result<UniversalParams<E>, Error> {
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }
        let beta = E::Fr::rand(rng);
        let g = E::G1Projective::rand(rng);
        let gamma_g = E::G1Projective::rand(rng);
        let h = E::G2Projective::rand(rng);

        let mut powers_of_beta = vec![E::Fr::one()];

        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

        let scalar_bits = E::Fr::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &powers_of_beta,
        );
        let gamma_g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
        let mut powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &gamma_g_table,
            &powers_of_beta,
        );
        // Add an additional power of gamma_g, because we want to be able to support
        // up to D queries.
        powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));

        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);
        let powers_of_gamma_g =
            E::G1Projective::batch_normalization_into_affine(&powers_of_gamma_g)
                .into_iter()
                .enumerate()
                .collect();

        let h = h.into_affine();
        let beta_h = h.mul(beta).into_affine();
        let prepared_h = h.into();
        let prepared_beta_h = beta_h.into();

        let pp = UniversalParams {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        };
        Ok(pp)
    }

    /// Outputs a commitment to `polynomial`.
    pub fn commit(powers: &Powers<E>, polynomial: &P) -> Result<Commitment<E>, Error> {
        Self::check_degree_is_too_large(polynomial.degree(), powers.size())?;

        let (num_leading_zeros, plain_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(polynomial);

        let commitment = VariableBaseMSM::multi_scalar_mul(
            &powers.powers_of_g[num_leading_zeros..],
            &plain_coeffs,
        );

        Ok(Commitment(commitment.into()))
    }

    /// Compute witness polynomial.
    ///
    /// The witness polynomial w(x) the quotient of the division (p(x) - p(z)) / (x - z)
    /// Observe that this quotient does not change with z because
    /// p(z) is the remainder term. We can therefore omit p(z) when computing the quotient.
    pub fn compute_witness_polynomial(p: &P, point: P::Point) -> Result<P, Error> {
        let divisor = P::from_coefficients_vec(vec![-point, E::Fr::one()]);

        let witness_polynomial = p / &divisor;

        Ok(witness_polynomial)
    }

    pub fn open_with_witness_polynomial<'a>(
        powers: &Powers<E>,
        witness_polynomial: &P,
    ) -> Result<Proof<E>, Error> {
        Self::check_degree_is_too_large(witness_polynomial.degree(), powers.size())?;
        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(witness_polynomial);

        let w = VariableBaseMSM::multi_scalar_mul(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        Ok(Proof { w: w.into_affine() })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the same.
    pub fn open<'a>(powers: &Powers<E>, p: &P, point: P::Point) -> Result<Proof<E>, Error> {
        Self::check_degree_is_too_large(p.degree(), powers.size())?;

        let witness_poly = Self::compute_witness_polynomial(p, point)?;

        let proof = Self::open_with_witness_polynomial(powers, &witness_poly);

        proof
    }

    /// Verifies that `value` is the evaluation at `point` of the polynomial
    /// committed inside `comm`.
    pub fn check(
        vk: &VerifierKey<E>,
        comm: &Commitment<E>,
        point: E::Fr,
        value: E::Fr,
        proof: &Proof<E>,
    ) -> Result<bool, Error> {
        let inner = comm.0.into_projective() - &vk.g.mul(value);
        let lhs = E::pairing(inner, vk.h);

        let inner = vk.beta_h.into_projective() - &vk.h.mul(point);
        let rhs = E::pairing(proof.w, inner);

        Ok(lhs == rhs)
    }

    /// Check that each `proof_i` in `proofs` is a valid proof of evaluation for
    /// `commitment_i` at `point_i`.
    pub fn batch_check<R: RngCore>(
        vk: &VerifierKey<E>,
        commitments: &[Commitment<E>],
        points: &[E::Fr],
        values: &[E::Fr],
        proofs: &[Proof<E>],
        rng: &mut R,
    ) -> Result<bool, Error> {
        let mut total_c = <E::G1Projective>::zero();
        let mut total_w = <E::G1Projective>::zero();

        let mut randomizer = E::Fr::one();
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::Fr::zero();
        let gamma_g_multiplier = E::Fr::zero();
        for (((c, z), v), proof) in commitments.iter().zip(points).zip(values).zip(proofs) {
            let w = proof.w;
            let mut temp = w.mul(*z);
            temp.add_assign_mixed(&c.0);
            let c = temp;
            g_multiplier += &(randomizer * v);
            total_c += &c.mul(randomizer.into_repr());
            total_w += &w.mul(randomizer.into_repr());
            // We don't need to sample randomizers from the full field,
            // only from 128-bit strings.
            randomizer = u128::rand(rng).into();
        }
        total_c -= &vk.g.mul(g_multiplier);
        total_c -= &vk.gamma_g.mul(gamma_g_multiplier);

        let affine_points = E::G1Projective::batch_normalization_into_affine(&[-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);

        let result = E::product_of_pairings(&[
            (total_w.into(), vk.prepared_beta_h.clone()),
            (total_c.into(), vk.prepared_h.clone()),
        ])
        .is_one();
        Ok(result)
    }

    pub(crate) fn check_degree_is_too_large(degree: usize, num_powers: usize) -> Result<(), Error> {
        let num_coefficients = degree + 1;
        if num_coefficients > num_powers {
            Err(Error::TooManyCoefficients {
                num_coefficients,
                num_powers,
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_degrees_and_bounds<'a>(
        supported_degree: usize,
        max_degree: usize,
        enforced_degree_bounds: Option<&[usize]>,
        p: &'a LabeledPolynomial<E::Fr, P>,
    ) -> Result<(), Error> {
        if let Some(bound) = p.degree_bound() {
            let enforced_degree_bounds =
                enforced_degree_bounds.ok_or(Error::UnsupportedDegreeBound(bound))?;

            if enforced_degree_bounds.binary_search(&bound).is_err() {
                Err(Error::UnsupportedDegreeBound(bound))
            } else if bound < p.degree() || bound > max_degree {
                return Err(Error::IncorrectDegreeBound {
                    poly_degree: p.degree(),
                    degree_bound: p.degree_bound().unwrap(),
                    supported_degree,
                    label: p.label().to_string(),
                });
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: UVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    coeffs
}

#[cfg(test)]
mod tests {
    #![allow(non_camel_case_types)]
    use super::*;

    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_bls12_381::G1Projective;
    use ark_ec::PairingEngine;
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use ark_poly::EvaluationDomain;
    use ark_poly::Polynomial;
    use ark_poly::Radix2EvaluationDomain;
    use ark_poly_commit::PCCommitment;
    use ark_std::test_rng;

    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;
    type UniPoly_377 = DensePoly<<Bls12_377 as PairingEngine>::Fr>;
    type KZG_Bls12_381 = KZG10<Bls12_381, UniPoly_381>;

    impl<E: PairingEngine, P: UVPolynomial<E::Fr>> KZG10<E, P> {
        /// Specializes the public parameters for a given maximum degree `d` for polynomials
        /// `d` should be less that `pp.max_degree()`.
        pub(crate) fn trim(
            pp: &UniversalParams<E>,
            mut supported_degree: usize,
        ) -> Result<(Powers<E>, VerifierKey<E>), Error> {
            if supported_degree == 1 {
                supported_degree += 1;
            }
            let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
            let powers_of_gamma_g = (0..=supported_degree)
                .map(|i| pp.powers_of_gamma_g[&i])
                .collect();

            let powers = Powers {
                powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
            };
            let vk = VerifierKey {
                g: pp.powers_of_g[0],
                gamma_g: pp.powers_of_gamma_g[&0],
                h: pp.h,
                beta_h: pp.beta_h,
                prepared_h: pp.prepared_h.clone(),
                prepared_beta_h: pp.prepared_beta_h.clone(),
            };
            Ok((powers, vk))
        }
    }

    #[test]
    fn add_commitments_test() {
        let rng = &mut test_rng();
        let p = DensePoly::from_coefficients_slice(&[
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
        ]);
        let f = Fr::rand(rng);
        let mut f_p = DensePoly::zero();
        f_p += (f, &p);

        let degree = 4;
        let pp = KZG_Bls12_381::setup(degree, false, rng).unwrap();
        let (powers, _) = KZG_Bls12_381::trim(&pp, degree).unwrap();

        let comm = KZG10::commit(&powers, &p).unwrap();
        let f_comm = KZG10::commit(&powers, &f_p).unwrap();
        let mut f_comm_2 = Commitment::empty();
        f_comm_2 += (f, &comm);

        assert_eq!(f_comm, f_comm_2);
    }

    fn end_to_end_test_template<E, P>() -> Result<(), Error>
    where
        E: PairingEngine,
        P: UVPolynomial<E::Fr, Point = E::Fr>,
        for<'a, 'b> &'a P: Div<&'b P, Output = P>,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = KZG10::<E, P>::setup(degree, false, rng)?;
            let (ck, vk) = KZG10::<E, P>::trim(&pp, degree)?;
            let p = P::rand(degree, rng);
            let comm = KZG10::<E, P>::commit(&ck, &p)?;
            let point = E::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof = KZG10::<E, P>::open(&ck, &p, point)?;
            assert!(
                KZG10::<E, P>::check(&vk, &comm, point, value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            );
        }
        Ok(())
    }

    fn linear_polynomial_test_template<E, P>() -> Result<(), Error>
    where
        E: PairingEngine,
        P: UVPolynomial<E::Fr, Point = E::Fr>,
        for<'a, 'b> &'a P: Div<&'b P, Output = P>,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let degree = 50;
            let pp = KZG10::<E, P>::setup(degree, false, rng)?;
            let (ck, vk) = KZG10::<E, P>::trim(&pp, 2)?;
            let p = P::rand(1, rng);
            let comm = KZG10::<E, P>::commit(&ck, &p)?;
            let point = E::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof = KZG10::<E, P>::open(&ck, &p, point)?;
            assert!(
                KZG10::<E, P>::check(&vk, &comm, point, value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            );
        }
        Ok(())
    }

    fn batch_check_test_template<E, P>() -> Result<(), Error>
    where
        E: PairingEngine,
        P: UVPolynomial<E::Fr, Point = E::Fr>,
        for<'a, 'b> &'a P: Div<&'b P, Output = P>,
    {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = KZG10::<E, P>::setup(degree, false, rng)?;
            let (ck, vk) = KZG10::<E, P>::trim(&pp, degree)?;
            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();
            for _ in 0..10 {
                let p = P::rand(degree, rng);
                let comm = KZG10::<E, P>::commit(&ck, &p)?;
                let point = E::Fr::rand(rng);
                let value = p.evaluate(&point);
                let proof = KZG10::<E, P>::open(&ck, &p, point)?;

                assert!(KZG10::<E, P>::check(&vk, &comm, point, value, &proof)?);
                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }
            assert!(KZG10::<E, P>::batch_check(
                &vk, &comms, &points, &values, &proofs, rng
            )?);
        }
        Ok(())
    }

    #[test]
    fn end_to_end_test() {
        end_to_end_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
        end_to_end_test_template::<Bls12_381, UniPoly_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn linear_polynomial_test() {
        linear_polynomial_test_template::<Bls12_377, UniPoly_377>()
            .expect("test failed for bls12-377");
        linear_polynomial_test_template::<Bls12_381, UniPoly_381>()
            .expect("test failed for bls12-381");
    }
    #[test]
    fn batch_check_test() {
        batch_check_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
        batch_check_test_template::<Bls12_381, UniPoly_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn test_degree_is_too_large() {
        let rng = &mut test_rng();

        let max_degree = 123;
        let pp = KZG_Bls12_381::setup(max_degree, false, rng).unwrap();
        let (powers, _) = KZG_Bls12_381::trim(&pp, max_degree).unwrap();

        let p = DensePoly::<Fr>::rand(max_degree + 1, rng);
        assert!(p.degree() > max_degree);
        assert!(KZG_Bls12_381::check_degree_is_too_large(p.degree(), powers.size()).is_err());
    }

    #[test]
    fn commit_linear_extension() {
        const N: usize = 4;
        let rng = &mut test_rng();

        let max_degree = N - 1; // Length 4 poly
        let pp = KZG_Bls12_381::setup(max_degree, false, rng).unwrap();
        let (powers, vk) = KZG_Bls12_381::trim(&pp, max_degree).unwrap();
        let domain_n = <Radix2EvaluationDomain<Fr>>::new(N).expect("Failed to make N domain");
        let domain_2n = <Radix2EvaluationDomain<Fr>>::new(2 * N).expect("Failed to make 2N domain");

        let mut grid = vec![vec![Fr::zero(); N]; N];
        for i in 0..4 {
            for j in 0..4 {
                grid[i][j] = Fr::rand(rng);
            }
        }
        // commit along rows before extending
        let (mut commits, mut col0_opens): (Vec<_>, Vec<_>) = grid
            .iter()
            .map(|row| {
                let coeffs = domain_n.ifft(&row);
                let poly = DensePoly { coeffs };
                (
                    KZG10::commit(&powers, &poly)
                        .expect("Failed to commit to poly")
                        .0
                        .into_projective(),
                    KZG10::open(&powers, &poly, domain_n.element(0))
                        .expect("Failed to open")
                        .w
                        .into_projective(),
                )
            })
            .unzip();

        // Extend grid elements column wise
        let mut extended_grid = vec![vec![Fr::zero(); N]; 2 * N];
        for j in 0..N {
            let mut col_evals = (0..N).map(|i| grid[i][j].clone()).collect::<Vec<_>>();
            domain_n.ifft_in_place(&mut col_evals);
            domain_2n.fft_in_place(&mut col_evals);
            assert_eq!(col_evals.len(), 2 * N);
            for i in 0..(2 * N) {
                extended_grid[i][j] = col_evals[i];
            }
        }

        // Extend commitments
        domain_n.ifft_in_place(&mut commits);
        domain_2n.fft_in_place(&mut commits);

        // Extend openings
        domain_n.ifft_in_place(&mut col0_opens);
        domain_2n.fft_in_place(&mut col0_opens);

        // Check commitments
        for i in 0..extended_grid.len() {
            let coeffs = domain_n.ifft(&extended_grid[i]);
            let res_commit = KZG10::commit(&powers, &DensePoly { coeffs }).expect("Failed commit");
            assert_eq!(res_commit.0, commits[i].into_affine());
            assert!(<KZG10<Bls12_381, DensePoly<Fr>>>::check(
                &vk,
                &res_commit,
                domain_n.element(0),
                extended_grid[i][0],
                &Proof {
                    w: col0_opens[i].into_affine()
                },
            )
            .expect("Failed to check"));
        }
    }
}
