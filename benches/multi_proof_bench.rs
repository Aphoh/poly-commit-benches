use ark_bls12_381_04::Bls12_381;
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};
use poly_commit_benches::{
    ark::{
        kzg_multiproof_bench::{Multiproof1Bench, Multiproof2Bench},
        streaming_kzg_bench::StreamingKzgBench,
    },
    PcBench,
};

pub fn open_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("open");
    do_open_bench::<StreamingKzgBench<Bls12_381, 4, 4>, _>(&mut group, "skzg_4_4", &[256]);
    do_open_bench::<StreamingKzgBench<Bls12_381, 8, 8>, _>(&mut group, "skzg_8_8", &[256]);
    do_open_bench::<StreamingKzgBench<Bls12_381, 16, 16>, _>(&mut group, "skzg_16_16", &[256]);
    do_open_bench::<StreamingKzgBench<Bls12_381, 32, 32>, _>(&mut group, "skzg_32_32", &[256]);
    do_open_bench::<StreamingKzgBench<Bls12_381, 64, 64>, _>(&mut group, "skzg_64_64", &[256]);
    do_open_bench::<StreamingKzgBench<Bls12_381, 128, 128>, _>(&mut group, "skzg_128_128", &[256]);

    do_open_bench::<Multiproof1Bench<Bls12_381, 4, 4>, _>(&mut group, "mp1_4_4", &[256]);
    do_open_bench::<Multiproof1Bench<Bls12_381, 8, 8>, _>(&mut group, "mp1_8_8", &[256]);
    do_open_bench::<Multiproof1Bench<Bls12_381, 16, 16>, _>(&mut group, "mp1_16_16", &[256]);
    do_open_bench::<Multiproof1Bench<Bls12_381, 32, 32>, _>(&mut group, "mp1_32_32", &[256]);
    do_open_bench::<Multiproof1Bench<Bls12_381, 64, 64>, _>(&mut group, "mp1_64_64", &[256]);
    do_open_bench::<Multiproof1Bench<Bls12_381, 128, 128>, _>(&mut group, "mp1_128_128", &[256]);

    do_open_bench::<Multiproof2Bench<Bls12_381, 4, 4>, _>(&mut group, "mp2_4_4", &[256]);
    do_open_bench::<Multiproof2Bench<Bls12_381, 8, 8>, _>(&mut group, "mp2_8_8", &[256]);
    do_open_bench::<Multiproof2Bench<Bls12_381, 16, 16>, _>(&mut group, "mp2_16_16", &[256]);
    do_open_bench::<Multiproof2Bench<Bls12_381, 32, 32>, _>(&mut group, "mp2_32_32", &[256]);
    do_open_bench::<Multiproof2Bench<Bls12_381, 64, 64>, _>(&mut group, "mp2_64_64", &[256]);
    do_open_bench::<Multiproof2Bench<Bls12_381, 128, 128>, _>(&mut group, "mp2_128_128", &[256]);
}

pub fn verify_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    do_verify_bench::<StreamingKzgBench<Bls12_381, 4, 4>, _>(&mut group, "skzg_4_4", &[256]);
    do_verify_bench::<StreamingKzgBench<Bls12_381, 8, 8>, _>(&mut group, "skzg_8_8", &[256]);
    do_verify_bench::<StreamingKzgBench<Bls12_381, 16, 16>, _>(&mut group, "skzg_16_16", &[256]);
    do_verify_bench::<StreamingKzgBench<Bls12_381, 32, 32>, _>(&mut group, "skzg_32_32", &[256]);
    do_verify_bench::<StreamingKzgBench<Bls12_381, 64, 64>, _>(&mut group, "skzg_64_64", &[256]);
    do_verify_bench::<StreamingKzgBench<Bls12_381, 128, 128>, _>(
        &mut group,
        "skzg_128_128",
        &[256],
    );

    do_verify_bench::<Multiproof1Bench<Bls12_381, 4, 4>, _>(&mut group, "mp1_4_4", &[256]);
    do_verify_bench::<Multiproof1Bench<Bls12_381, 8, 8>, _>(&mut group, "mp1_8_8", &[256]);
    do_verify_bench::<Multiproof1Bench<Bls12_381, 16, 16>, _>(&mut group, "mp1_16_16", &[256]);
    do_verify_bench::<Multiproof1Bench<Bls12_381, 32, 32>, _>(&mut group, "mp1_32_32", &[256]);
    do_verify_bench::<Multiproof1Bench<Bls12_381, 64, 64>, _>(&mut group, "mp1_64_64", &[256]);
    do_verify_bench::<Multiproof1Bench<Bls12_381, 128, 128>, _>(&mut group, "mp1_128_128", &[256]);

    do_verify_bench::<Multiproof2Bench<Bls12_381, 4, 4>, _>(&mut group, "mp2_4_4", &[256]);
    do_verify_bench::<Multiproof2Bench<Bls12_381, 8, 8>, _>(&mut group, "mp2_8_8", &[256]);
    do_verify_bench::<Multiproof2Bench<Bls12_381, 16, 16>, _>(&mut group, "mp2_16_16", &[256]);
    do_verify_bench::<Multiproof2Bench<Bls12_381, 32, 32>, _>(&mut group, "mp2_32_32", &[256]);
    do_verify_bench::<Multiproof2Bench<Bls12_381, 64, 64>, _>(&mut group, "mp2_64_64", &[256]);
    do_verify_bench::<Multiproof2Bench<Bls12_381, 128, 128>, _>(&mut group, "mp2_128_128", &[256]);
}

pub fn do_open_bench<B: PcBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
    poly_degrees: &[usize],
) {
    let mut setup = B::setup(256);
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

pub fn do_verify_bench<B: PcBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
    poly_degrees: &[usize],
) {
    let mut setup = B::setup(256);
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

criterion_group!(benches, open_bench, verify_bench);
criterion_main!(benches);
