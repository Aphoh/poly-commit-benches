use std::marker::PhantomData;

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::thread_rng;

use crate::ErasureEncodeBench;

pub type Bls12_381ScalarFftBench = FftFieldBench<ark_bls12_381::Fr>;
pub type Bls12_377ScalarFftBench = FftFieldBench<ark_bls12_377::Fr>;
pub type Bn254ScalarFftBench = FftFieldBench<ark_bn254::Fr>;

pub struct FftFieldBench<Fr>(PhantomData<Fr>);

impl<Fr: FftField> ErasureEncodeBench for FftFieldBench<Fr> {
    type Domain = Radix2EvaluationDomain<Fr>;
    type Points = Vec<Fr>;

    // Size should be a power of 2 here
    fn make_domain(size: usize) -> Self::Domain {
        Radix2EvaluationDomain::new(size).expect("Failed to construct evaluation domain")
    }

    fn rand_points(size: usize) -> Self::Points {
        (0..size).map(|_| Fr::rand(&mut thread_rng())).collect()
    }

    // `pts` must be the same size as `sub_domain`
    // The `i`-th point of the input will be the same as the
    // `i * big_domain.size()/sub_domain.size()`-th point of the output
    fn erasure_encode(
        pts: &mut Self::Points,
        sub_domain: &Self::Domain,
        big_domain: &Self::Domain,
    ) {
        assert_eq!(sub_domain.size(), pts.len());
        assert_eq!(sub_domain.size() % sub_domain.size(), 0); // Domain a must divide domain b
        sub_domain.ifft_in_place(pts);
        pts.resize(big_domain.size(), Fr::zero());
        big_domain.fft_in_place(pts);
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use rand::thread_rng;

    #[test]
    fn test_interp_bench() {
        // TODO
    }

    #[test]
    fn test_domain_encoding() {
        let domain_4 = <Radix2EvaluationDomain<Fr>>::new(4).unwrap();
        let domain_8 = <Radix2EvaluationDomain<Fr>>::new(8).unwrap();

        let d4_evals: Vec<_> = (0..4).map(|_| Fr::rand(&mut thread_rng())).collect();
        let d4_coeffs = domain_4.ifft(&d4_evals);
        let mut d8_coeffs = vec![Fr::zero(); 8];
        for (i, coeff) in d4_coeffs.iter().enumerate() {
            d8_coeffs[i] = *coeff;
        }
        let d8_evals = domain_8.fft(&d8_coeffs);
        let size_scale = domain_8.size() / domain_4.size();
        for (j, d4_eval) in d4_evals.iter().enumerate() {
            assert_eq!(d4_eval, &d8_evals[size_scale * j]);
        }
    }
}
