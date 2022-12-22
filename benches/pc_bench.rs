use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};
use poly_commit_benches::{
    ark::kzg_bench::*,
    plonk_kzg::PlonkKZG,
    PcBench,
};

const LOG_MIN_DEG: usize = 5;
const LOG_MAX_DEG: usize = 12;
const MAX_DEG: usize = 2usize.pow(LOG_MAX_DEG as u32);

pub fn open_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("open");
    do_open_bench::<KzgBls12_377Bench, _>(&mut group, "ark_kzg_bls12_377");
    do_open_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381");
    do_open_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254");
    do_open_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381");
}

pub fn commit_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    do_commit_bench::<KzgBls12_377Bench, _>(&mut group, "ark_kzg_bls12_377");
    do_commit_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381");
    do_commit_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254");
    do_commit_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381");
}

pub fn verify_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    do_verify_bench::<KzgBls12_377Bench, _>(&mut group, "ark_kzg_bls12_377");
    do_verify_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381");
    do_verify_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254");
    do_verify_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381");
}

pub fn do_open_bench<B: PcBench, M: Measurement>(g: &mut BenchmarkGroup<'_, M>, suite_name: &str) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in (LOG_MIN_DEG..LOG_MAX_DEG).map(|i| 2usize.pow(i as u32)) {
        g.throughput(throughput::<B>(s));
        let trim = B::trim(&setup, s);
        let (poly, point, _) = B::rand_poly(&mut setup, s);
        g.bench_with_input(
            BenchmarkId::new(format!("{}_{}", suite_name, "open"), s),
            &s,
            |b, &_| {
                b.iter(|| {
                    B::open(&trim, &mut setup, &poly, &point);
                })
            },
        );
    }
}

pub fn do_commit_bench<B: PcBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in (LOG_MIN_DEG..LOG_MAX_DEG).map(|i| 2usize.pow(i as u32)) {
        g.throughput(throughput::<B>(s));
        let trim = B::trim(&setup, s);
        let (poly, _, _) = B::rand_poly(&mut setup, s);
        g.bench_with_input(
            BenchmarkId::new(format!("{}_{}", suite_name, "commit"), s),
            &s,
            |b, &_| {
                b.iter(|| {
                    B::commit(&trim, &mut setup, &poly);
                })
            },
        );
    }
}

pub fn do_verify_bench<B: PcBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in (LOG_MIN_DEG..LOG_MAX_DEG).map(|i| 2usize.pow(i as u32)) {
        g.throughput(throughput::<B>(s));
        let trim = B::trim(&setup, s);
        let (poly, point, value) = B::rand_poly(&mut setup, s);
        let commit = B::commit(&trim, &mut setup, &poly);
        let open = B::open(&trim, &mut setup, &poly, &point);
        g.bench_with_input(
            BenchmarkId::new(format!("{}_{}", suite_name, "verify"), s),
            &s,
            |b, &_| {
                b.iter(|| {
                    B::verify(&trim, &commit, &open, &value, &point);
                })
            },
        );
    }
}

fn throughput<B: PcBench>(poly_deg: usize) -> Throughput {
    let a = (poly_deg + 1) * (B::bytes_per_elem() - 1);
    Throughput::Bytes(a as u64)
}

criterion_group!(benches, open_bench, commit_bench, verify_bench,);
criterion_main!(benches);
