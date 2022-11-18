use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use poly_commit_benches::{
    ark::marlin::{MarlinBls12_377Bench, MarlinBls12_381Bench, MarlinBn254Bench},
    plonk_kzg::PlonkKZG,
    Bench,
};

const LOG_MAX_DEG: usize = 12;
const MAX_DEG: usize = 2usize.pow(LOG_MAX_DEG as u32);

pub fn ark_marlin_bls12_381(c: &mut Criterion) {
    do_bench::<MarlinBls12_381Bench>(c, "ark_marlin_bls12_381");
}

pub fn ark_marlin_bls12_377(c: &mut Criterion) {
    do_bench::<MarlinBls12_377Bench>(c, "ark_marlin_bls12_377");
}

pub fn ark_marlin_bn254(c: &mut Criterion) {
    do_bench::<MarlinBn254Bench>(c, "ark_marlin_bn254");
}

pub fn plonk_kzg_bls12_381(c: &mut Criterion) {
    do_bench::<PlonkKZG>(c, "plonk_kzg_bls12_381");
}

pub fn do_bench<B: Bench>(c: &mut Criterion, base_name: &str) {
    let mut group = c.benchmark_group(base_name);
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in (3..LOG_MAX_DEG).map(|i| 2usize.pow(i as u32)) {
        group.throughput(throughput::<B>(s));

        let trim = B::trim(&setup, s);
        let (poly, point, value) = B::rand_poly(&mut setup, s);
        group.bench_with_input(BenchmarkId::new("commit", s), &s, |b, &_| {
            b.iter(|| {
                B::commit(&trim, &mut setup, &poly);
            })
        });
        group.bench_with_input(BenchmarkId::new("open", s), &s, |b, &_| {
            b.iter(|| {
                B::open(&trim, &mut setup, &poly, &point);
            })
        });
        let commit = B::commit(&trim, &mut setup, &poly);
        let open = B::open(&trim, &mut setup, &poly, &point);
        group.bench_with_input(BenchmarkId::new("verify", s), &s, |b, &_| {
            b.iter(|| {
                B::verify(&trim, &commit, &open, &value, &point);
            })
        });
    }
}

fn throughput<B: Bench>(poly_deg: usize) -> Throughput {
    let a = (poly_deg + 1) * (B::bytes_per_elem() - 1);
    Throughput::Bytes(a as u64)
}

criterion_group!(
    benches,
    plonk_kzg_bls12_381,
    ark_marlin_bls12_381,
    ark_marlin_bls12_377,
    ark_marlin_bn254,
);
criterion_main!(benches);
