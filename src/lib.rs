pub mod ark;
pub mod plonk_kzg;
pub(crate) use ark_std::test_rng;
pub(crate) use rand::rngs::StdRng;

pub trait Bench {
    type Setup;
    type Trimmed;
    type Poly;
    type Point;
    type Commit;
    type Proof;
    fn setup(max_degree: usize) -> Self::Setup;
    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed;
    // Random (p, z, p(z))
    fn rand_poly(s: &mut Self::Setup, d: usize) -> (Self::Poly, Self::Point, Self::Point);
    fn bytes_per_elem() -> usize;
    fn commit(t: &Self::Trimmed, s: &mut Self::Setup, p: &Self::Poly) -> Self::Commit;
    fn open(
        t: &Self::Trimmed,
        s: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof;
    fn verify(
        t: &Self::Trimmed,
        c: &Self::Commit,
        proof: &Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool;
}

#[cfg(test)]
fn test_works<T: Bench>() {
    const BASE_DEG: usize = 2usize.pow(8);
    const TRIM_DEG: usize = 2usize.pow(6);
    let mut s = T::setup(BASE_DEG);
    let t = T::trim(&s, TRIM_DEG);
    let (poly, point, value) = T::rand_poly(&mut s, TRIM_DEG);
    let c = T::commit(&t, &mut s, &poly);
    let p = T::open(&t, &mut s, &poly, &point);
    assert!(T::verify(&t, &c, &p, &value, &point));
}
