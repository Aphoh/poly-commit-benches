pub mod ark;

pub const MAX_DEG: u32 = 100;

pub trait Bench {
    type Setup;
    type Trimmed;
    type Poly;
    type Point;
    type Commit;
    type Proof;
    fn setup(max_degree: usize) -> Self::Setup;
    fn trim(s: &Self::Setup, supported_degree: usize) -> Self::Trimmed;
    fn rand_poly(s: &mut Self::Setup, d: usize) -> Self::Poly;
    fn eval_poly(poly: &Self::Poly, pt: &Self::Point) -> Self::Point;
    fn rand_point(s: &mut Self::Setup) -> Self::Point;
    fn commit(t: &Self::Trimmed, s: &mut Self::Setup, p: &Self::Poly) -> Self::Commit;
    fn open(
        t: &Self::Trimmed,
        s: &mut Self::Setup,
        p: &Self::Poly,
        pt: &Self::Point,
    ) -> Self::Proof;
    fn verify(
        t: &Self::Trimmed,
        c: Self::Commit,
        proof: Self::Proof,
        value: &Self::Point,
        pt: &Self::Point,
    ) -> bool;
}

#[cfg(test)]
fn test_works<T: Bench>() {
    let mut s = T::setup(100);
    let t = T::trim(&s, 50);
    let poly = T::rand_poly(&mut s, 50);
    let c = T::commit(&t, &mut s, &poly);
    let pt = T::rand_point(&mut s);
    let p = T::open(&t, &mut s, &poly, &pt);
    let value = T::eval_poly(&poly, &pt);
    assert!(T::verify(&t, c, p, &value, &pt));
}
