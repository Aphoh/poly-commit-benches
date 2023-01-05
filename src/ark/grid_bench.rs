use std::marker::PhantomData;

use ark_bls12_381::Bls12_381;
use ark_ec::{PairingEngine, AffineCurve};
use ark_ff::UniformRand;
use ark_poly::{
    domain::DomainCoeff, univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, Zero};
use rand::distributions::uniform::SampleRange;

use crate::GridBench;

use super::kzg::{Powers, KZG10};

pub struct KzgGridBench<E>(PhantomData<E>);
pub type KzgGridBenchBls12_381 = KzgGridBench<Bls12_381>;

#[derive(Debug, Clone)]
pub struct Setup<E: PairingEngine> {
    powers: Powers<E>,
    domain_n: Radix2EvaluationDomain<E::Fr>,
    domain_2n: Radix2EvaluationDomain<E::Fr>,
}

type KZGFor<E> = KZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>;

impl<E> GridBench for KzgGridBench<E>
where
    E: PairingEngine,
    E::G1Projective: DomainCoeff<E::Fr>,
{
    type Setup = Setup<E>;
    type Grid = Vec<Vec<E::Fr>>;
    type ExtendedGrid = Vec<Vec<E::Fr>>;
    type Commits = Vec<E::G1Projective>;
    type Opens = Vec<E::G1Projective>;

    fn do_setup(size: usize) -> Self::Setup {
        let up = <KZGFor<E>>::setup(size - 1, &mut test_rng()).unwrap();
        let (powers, _) = <KZGFor<E>>::trim(&up, size - 1).unwrap();
        Self::Setup {
            powers,
            domain_n: Radix2EvaluationDomain::new(size).expect("Failed to make n domain"),
            domain_2n: Radix2EvaluationDomain::new(2 * size).expect("Failed to make 2n domain"),
        }
    }

    fn rand_grid(size: usize) -> Self::Grid {
        let mut grid = vec![vec![Zero::zero(); size]; size];
        for i in 0..size {
            for j in 0..size {
                grid[i][j] = UniformRand::rand(&mut test_rng());
            }
        }
        grid
    }

    fn extend_grid(s: &Self::Setup, g: &Self::Grid) -> Self::ExtendedGrid {
        let mut eg = vec![vec![Zero::zero(); g.len()]; 2 * g.len()];
        // for each column
        for j in 0..g.len() {
            // collect into a vec
            let mut col = (0..g.len()).map(|i| g[i][j]).collect::<Vec<_>>();
            // erasure encode
            s.domain_n.ifft_in_place(&mut col);
            s.domain_2n.fft_in_place(&mut col);
            // copy into extended grid
            for i in 0..col.len() {
                eg[i][j] = col[i];
            }
        }
        eg
    }

    fn make_commits(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Commits {
        let mut commits = Vec::new();
        // Collect commits to original rows
        for i in 0..g.len() / 2 {
            let c = <KZGFor<E>>::commit(
                &s.powers,
                &DensePolynomial {
                    coeffs: g[2 * i].clone(), //TODO: rewrite KZG api to bypass clone
                },
            )
            .expect("Failed to commit");
            commits.push(c.0.into_projective());
        }
        // Extend commits
        s.domain_n.ifft_in_place(&mut commits);
        s.domain_2n.fft_in_place(&mut commits);
        commits
    }

    fn open_column(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Opens {
        let n = g.len() / 2;
        // Collect underlying polys
        let polys: Vec<_> = (0..n)
            .map(|i| DensePolynomial {
                coeffs: g[2 * i].clone(),
            })
            .collect();
        let j = (0..n).sample_single(&mut test_rng());
        let pt = s.domain_n.element(j);
        let mut col_opens = Vec::new();
        // for each row
        for i in 0..n {
            // open at (row, column)
            let open = <KZGFor<E>>::open(&s.powers, &polys[i], pt)
                .expect("Failed to open");
            col_opens.push(open.w.into_projective());
        }
        // fft to get all opens
        s.domain_n.ifft_in_place(&mut col_opens);
        s.domain_2n.fft_in_place(&mut col_opens);
        // copy in to bigger opens matrix
        col_opens
    }

    fn bytes_per_elem() -> usize {
        E::Fr::zero().serialized_size() - 1
    }
}
