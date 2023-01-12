use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};
use poly_commit_benches::{
    ark::{kzg_bench::*, marlin_bench::*, streaming_kzg_bench::StreamingKzgBench},
    plonk_kzg::PlonkKZG,
    PcBench,
};

const LOG_MIN_DEG: usize = 5;
const LOG_MAX_DEG: usize = 12;
const MAX_DEG: usize = 2usize.pow(LOG_MAX_DEG as u32);

pub fn open_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("open");
    let poly_degrees: Vec<_> = (LOG_MIN_DEG..LOG_MAX_DEG)
        .into_iter()
        .map(|s| 2usize.pow(s as u32))
        .collect();
    do_open_bench::<MarlinBls12_381Bench, _>(&mut group, "ark_marlin_bls12_381", &poly_degrees);
    do_open_bench::<MarlinBn254Bench, _>(&mut group, "ark_marlin_bn254", &poly_degrees);
    do_open_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381", &poly_degrees);
    do_open_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254", &poly_degrees);
    do_open_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381", &poly_degrees);
}

pub fn commit_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    let poly_degrees: Vec<_> = (LOG_MIN_DEG..LOG_MAX_DEG)
        .into_iter()
        .map(|s| 2usize.pow(s as u32))
        .collect();
    do_commit_bench::<MarlinBls12_381Bench, _>(&mut group, "ark_marlin_bls12_381", &poly_degrees);
    do_commit_bench::<MarlinBn254Bench, _>(&mut group, "ark_marlin_bn254", &poly_degrees);
    do_commit_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381", &poly_degrees);
    do_commit_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254", &poly_degrees);
    do_commit_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381", &poly_degrees);
}

pub fn verify_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    let poly_degrees: Vec<_> = (LOG_MIN_DEG..LOG_MAX_DEG)
        .into_iter()
        .map(|s| 2usize.pow(s as u32))
        .collect();
    do_verify_bench::<MarlinBls12_381Bench, _>(&mut group, "ark_marlin_bls12_381", &poly_degrees);
    do_verify_bench::<MarlinBn254Bench, _>(&mut group, "ark_marlin_bn254", &poly_degrees);
    do_verify_bench::<KzgBls12_381Bench, _>(&mut group, "ark_kzg_bls12_381", &poly_degrees);
    do_verify_bench::<KzgBn254Bench, _>(&mut group, "ark_kzg_bn254", &poly_degrees);
    do_verify_bench::<PlonkKZG, _>(&mut group, "plonk_kzg_bls12_381", &poly_degrees);
}

pub fn chunk_bench(c: &mut Criterion) {
    use ark_bls12_381_04::Bls12_381;
    {
        let mut group = c.benchmark_group("chunk_open");
        do_open_bench::<StreamingKzgBench<Bls12_381, 1, 5>, _>(&mut group, "skzg_1_5_256", &[256]);
        do_open_bench::<StreamingKzgBench<Bls12_381, 5, 1>, _>(&mut group, "skzg_5_1_256", &[256]);
        do_open_bench::<StreamingKzgBench<Bls12_381, 5, 5>, _>(&mut group, "skzg_5_5_256", &[256]);
        do_open_bench::<StreamingKzgBench<Bls12_381, 10, 5>, _>(
            &mut group,
            "skzg_10_5_256",
            &[256],
        );
        do_open_bench::<StreamingKzgBench<Bls12_381, 5, 10>, _>(
            &mut group,
            "skzg_5_10_256",
            &[256],
        );
        do_open_bench::<StreamingKzgBench<Bls12_381, 64, 64>, _>(
            &mut group,
            "skzg_64_64_256",
            &[256],
        );
        do_open_bench::<StreamingKzgBench<Bls12_381, 128, 128>, _>(
            &mut group,
            "skzg_128_128_256",
            &[256],
        );
    }
    {
        let mut group = c.benchmark_group("chunk_verify");
        do_verify_bench::<StreamingKzgBench<Bls12_381, 1, 5>, _>(
            &mut group,
            "skzg_1_5_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 5, 1>, _>(
            &mut group,
            "skzg_5_1_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 5, 5>, _>(
            &mut group,
            "skzg_5_5_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 10, 5>, _>(
            &mut group,
            "skzg_10_5_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 5, 10>, _>(
            &mut group,
            "skzg_5_10_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 64, 64>, _>(
            &mut group,
            "skzg_64_64_256",
            &[256],
        );
        do_verify_bench::<StreamingKzgBench<Bls12_381, 128, 128>, _>(
            &mut group,
            "skzg_128_128_256",
            &[256],
        );
    }
}

pub fn do_open_bench<B: PcBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
    poly_degrees: &[usize],
) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in poly_degrees {
        g.throughput(open_throughput::<B>());
        let trim = B::trim(&setup, *s);
        let (poly, point, _) = B::rand_poly(&mut setup, *s);
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
    poly_degrees: &[usize],
) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in poly_degrees {
        g.throughput(throughput::<B>(*s));
        let trim = B::trim(&setup, *s);
        let (poly, _, _) = B::rand_poly(&mut setup, *s);
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
    poly_degrees: &[usize],
) {
    let mut setup = B::setup(MAX_DEG.try_into().unwrap());
    for s in poly_degrees {
        g.throughput(throughput::<B>(*s));
        let trim = B::trim(&setup, *s);
        let (poly, point, value) = B::rand_poly(&mut setup, *s);
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

fn open_throughput<B: PcBench>() -> Throughput {
    Throughput::Bytes(B::bytes_per_elem() as u64)
}

criterion_group!(benches, chunk_bench, open_bench, commit_bench, verify_bench);
criterion_main!(benches);
