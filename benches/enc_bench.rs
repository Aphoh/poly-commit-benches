use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion,
};
use poly_commit_benches::{
    ark::enc_bench as ark, plonk_kzg::enc_bench::PlonkEncBench, ErasureEncodeBench,
};

const LOG_MIN_DEG: usize = 6;
const LOG_MAX_DEG: usize = 12;

pub fn enc_bench(c: &mut Criterion) {
    {
        let mut g_scalar = c.benchmark_group("scalar_enc_bench");
        do_enc_bench::<ark::Bls12_381ScalarEncBench, _>(&mut g_scalar, "ark_bls12_381_scalar");
        do_enc_bench::<ark::Bn254ScalarEncBench, _>(&mut g_scalar, "ark_bn_254_scalar");
        do_enc_bench::<PlonkEncBench, _>(&mut g_scalar, "plonk_scalar");
    }
    {
        let mut g_pt = c.benchmark_group("pt_enc_bench");
        do_enc_bench::<ark::Bls12_381G1EncBench, _>(&mut g_pt, "ark_bls12_381_g1");
    }
}

pub fn do_enc_bench<B: ErasureEncodeBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    for size in (LOG_MIN_DEG..LOG_MAX_DEG).map(|i| 2usize.pow(i as u32)) {
        g.throughput(criterion::Throughput::Elements(size as u64));
        let s1 = B::make_domain(size);
        let s2 = B::make_domain(2 * size);
        let pts = B::rand_points(size);
        g.bench_with_input(BenchmarkId::new(suite_name, size), &size, |b, &_| {
            b.iter(|| {
                let mut pt2 = pts.clone();
                B::erasure_encode(&mut pt2, &s1, &s2)
            })
        });
    }
}

criterion_group!(enc_benches, enc_bench);
criterion_main!(enc_benches);
