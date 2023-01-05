use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion,
};
use poly_commit_benches::{ark::grid_bench::KzgGridBenchBls12_381, GridBench, plonk_kzg::grid_bench::PlonkGridBench};

const GRID_MIN_LOG_SIZE: usize = 4;
const GRID_MAX_LOG_SIZE: usize = 8;

pub fn grid_bench(c: &mut Criterion) {
    {
        let mut g_extend = c.benchmark_group("grid_extend");
        do_extend_bench::<KzgGridBenchBls12_381, _>(&mut g_extend, "ark_bls12_381");
        do_extend_bench::<PlonkGridBench, _>(&mut g_extend, "plonk");
    }
    {
        let mut g_commit = c.benchmark_group("grid_commit");
        do_commit_bench::<KzgGridBenchBls12_381, _>(&mut g_commit, "ark_bls12_381");
        do_commit_bench::<PlonkGridBench, _>(&mut g_commit, "plonk");
    }
    {
        let mut g_open = c.benchmark_group("grid_open_col");
        do_open_bench::<KzgGridBenchBls12_381, _>(&mut g_open, "ark_bls12_381");
        do_open_bench::<PlonkGridBench, _>(&mut g_open, "plonk");
    }
}

pub fn do_extend_bench<B: GridBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    for size in (GRID_MIN_LOG_SIZE..=GRID_MAX_LOG_SIZE).map(|i| 2usize.pow(i as u32)) {
        g.throughput(criterion::Throughput::Bytes(
            (size * size * B::bytes_per_elem()) as u64,
        ));
        let s = B::do_setup(size);
        let grid = B::rand_grid(size);
        g.bench_with_input(BenchmarkId::new(suite_name, size), &size, |b, &_| {
            b.iter(|| B::extend_grid(&s, &grid))
        });
    }
}

pub fn do_commit_bench<B: GridBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    for size in (GRID_MIN_LOG_SIZE..=GRID_MAX_LOG_SIZE).map(|i| 2usize.pow(i as u32)) {
        g.throughput(criterion::Throughput::Bytes(
            (size * size * B::bytes_per_elem()) as u64,
        ));
        let s = B::do_setup(size);
        let grid = B::rand_grid(size);
        let eg = B::extend_grid(&s, &grid);
        g.bench_with_input(BenchmarkId::new(suite_name, size), &size, |b, &_| {
            b.iter(|| B::make_commits(&s, &eg))
        });
    }
}

pub fn do_open_bench<B: GridBench, M: Measurement>(
    g: &mut BenchmarkGroup<'_, M>,
    suite_name: &str,
) {
    for size in (GRID_MIN_LOG_SIZE..=GRID_MAX_LOG_SIZE).map(|i| 2usize.pow(i as u32)) {
        g.throughput(criterion::Throughput::Bytes(
            (size * B::bytes_per_elem()) as u64,
        ));
        let s = B::do_setup(size);
        let grid = B::rand_grid(size);
        let eg = B::extend_grid(&s, &grid);
        g.bench_with_input(BenchmarkId::new(suite_name, size), &size, |b, &_| {
            b.iter(|| B::open_column(&s, &eg))
        });
    }
}

criterion_group!(grid_benches, grid_bench);
criterion_main!(grid_benches);
