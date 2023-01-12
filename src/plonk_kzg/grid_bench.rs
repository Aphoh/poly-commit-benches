use crate::test_rng;
use dusk_plonk::{
    bls12_381::G1Affine,
    commitment_scheme::kzg10::PublicParameters,
    fft::{self, EvaluationDomain},
    prelude::{BlsScalar, CommitKey},
};
use rand::distributions::uniform::SampleRange;

use crate::GridBench;

pub struct PlonkGridBench;

#[derive(Debug, Clone)]
pub struct Setup {
    ck: CommitKey,
    domain_n: EvaluationDomain,
    domain_2n: EvaluationDomain,
}

impl GridBench for PlonkGridBench {
    type Setup = Setup;
    type Grid = Vec<Vec<BlsScalar>>;
    type ExtendedGrid = Self::Grid;
    type Commits = Vec<G1Affine>;
    type Opens = Vec<G1Affine>;

    fn do_setup(size: usize) -> Self::Setup {
        let mut rng = crate::test_rng();
        let pp = PublicParameters::setup(size - 1, &mut rng).expect("Failed setup");
        let (ck, _) = pp.trim(size - 1).expect("Failed trim");
        let domain_n = EvaluationDomain::new(size).expect("Failed to make n domain");
        let domain_2n = EvaluationDomain::new(2 * size).expect("Failed to make n domain");
        Self::Setup {
            ck,
            domain_n,
            domain_2n,
        }
    }

    fn rand_grid(size: usize) -> Self::Grid {
        (0..size)
            .map(|_| {
                (0..size)
                    .map(|_| BlsScalar::random(&mut test_rng()))
                    .collect()
            })
            .collect()
    }

    fn extend_grid(s: &Self::Setup, g: &Self::Grid) -> Self::ExtendedGrid {
        let mut eg = vec![vec![BlsScalar::zero(); g.len()]; 2 * g.len()];
        // for each column
        for j in 0..g.len() {
            // collect into a vec
            let mut col = (0..g.len()).map(|i| g[i][j]).collect::<Vec<_>>();
            // erasure encode
            s.domain_n.ifft_in_place(&mut col);
            col = s.domain_2n.fft(&mut col); // Can't fft in place b/c plonk is silly
                                             // copy into extended grid
            for i in 0..col.len() {
                eg[i][j] = col[i];
            }
        }
        eg
    }

    fn make_commits(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Commits {
        g.iter()
            .map(|row| {
                let c =
                    s.ck.commit(&fft::Polynomial {
                        coeffs: row.clone(),
                    })
                    .expect("Commit failed");
                c.0
            })
            .collect()
    }

    fn open_column(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Opens {
        let n = g.len() / 2;
        let mut opens = vec![G1Affine::identity(); 2 * n];
        let j = (0..n).sample_single(&mut test_rng());
        let elem = s.domain_n.elements().nth(j).expect("Iterator ran out of elements");
        let polys = g.iter().map(|row| fft::Polynomial{ coeffs: row.clone() }).collect::<Vec<_>>();
        for i in 0..2*n {
            let wp = s.ck.compute_single_witness(&polys[i], &elem);
            opens[i] = s.ck.commit(&wp).expect("Open failed").0;
        }
        opens
    }

    fn bytes_per_elem() -> usize {
        31
    }
}
