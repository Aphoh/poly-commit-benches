use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use poly_commit_benches::ark;
use poly_commit_benches::Bench;

pub fn ark_marlin_bls12_381(c: &mut Criterion) {
    do_bench::<ark::marlin::MarlinBls12_381Bench>(c, "ark_marlin_bls12_381");
}

pub fn ark_marlin_bls12_377(c: &mut Criterion) {
    do_bench::<ark::marlin::MarlinBls12_377Bench>(c, "ark_marlin_bls12_377");
}

pub fn ark_marlin_bn254(c: &mut Criterion) {
    do_bench::<ark::marlin::MarlinBn254Bench>(c, "ark_marlin_bn254");
}

pub fn do_bench<B: Bench>(c: &mut Criterion, base_name: &str) {
    type B = ark::marlin::MarlinBls12_381Bench;
    let mut group = c.benchmark_group(format!("{}_open", base_name));
    let mut setup = B::setup(2usize.pow(16).try_into().unwrap());
    for s in (3..16).map(|i| 2usize.pow(i)) {
        group.throughput(Throughput::Elements(s as u64));

        let trim = B::trim(&setup, s);
        let poly = B::rand_poly(&mut setup, s);
        group.bench_with_input(BenchmarkId::from_parameter(s), &s, |b, &_| b.iter(|| {
            B::commit(&trim, &mut setup, &poly);
        }));
    }
}

criterion_group!(benches, ark_marlin_bls12_381, ark_marlin_bls12_377, ark_marlin_bn254);
criterion_main!(benches);
