pub mod ark;
pub mod plonk_kzg;
pub(crate) use ark_std::test_rng;
pub(crate) use rand::rngs::StdRng;

pub trait PcBench {
    type Setup;
    type Trimmed;
    type Poly;
    type Point;
    type Commit;
    type Proof;
    fn setup(max_degree: usize) -> Self::Setup;
    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed;
    // Random (poly, z, poly(z))
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

pub trait ErasureEncodeBench {
    type Domain: Clone;
    type Point: Clone;
   
    fn make_domain(size: usize) -> Self::Domain;
    fn rand_points(size: usize) -> Vec<Self::Point>;
    fn erasure_encode(pts: &mut Vec<Self::Point>, sub_domain: &Self::Domain, big_domain: &Self::Domain);
}

pub trait GridBench {
    type Setup: Clone;
    type Grid: Clone;
    type ExtendedGrid: Clone;
    type Commits;
    type Opens;
    fn do_setup(size: usize) -> Self::Setup;
    fn rand_grid(size: usize) -> Self::Grid;
    fn extend_grid(s: &Self::Setup, g: &Self::Grid) -> Self::ExtendedGrid;
    fn make_commits(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Commits;
    fn make_opens(s: &Self::Setup, g: &Self::ExtendedGrid) -> Self::Opens;
    fn bytes_per_elem() -> usize;
}

#[cfg(test)]
fn test_works<T: PcBench>() {
    const BASE_DEG: usize = 2usize.pow(8);
    const TRIM_DEG: usize = 2usize.pow(6);
    let mut s = T::setup(BASE_DEG);
    let t = T::trim(&s, TRIM_DEG);
    let (poly, point, value) = T::rand_poly(&mut s, TRIM_DEG);
    let c = T::commit(&t, &mut s, &poly);
    let p = T::open(&t, &mut s, &poly, &point);
    assert!(T::verify(&t, &c, &p, &value, &point));
}

#[cfg(test)]
fn test_enc_works<T: ErasureEncodeBench>() {
    let domain_a = T::make_domain(32);
    let domain_b = T::make_domain(64);
    let mut pts = T::rand_points(32);
    assert_eq!(pts.len(), 32);
    T::erasure_encode(&mut pts, &domain_a, &domain_b);
    assert_eq!(pts.len(), 64);
}
