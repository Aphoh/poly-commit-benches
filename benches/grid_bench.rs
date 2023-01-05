use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion,
};
use poly_commit_benches::{ark::grid_bench::KzgGridBenchBls12_381, GridBench};

const GRID_MIN_LOG_SIZE: usize = 4;
const GRID_MAX_LOG_SIZE: usize = 8;

pub fn grid_bench(c: &mut Criterion) {
    {
        let mut g_extend = c.benchmark_group("grid_extend");
        g_extend.sample_size(50).measurement_time(Duration::from_secs(3));
        do_extend_bench::<KzgGridBenchBls12_381, _>(&mut g_extend, "kzg_bls12_381");
    }
    {
        let mut g_commit = c.benchmark_group("grid_commit");
        g_commit.sample_size(25).measurement_time(Duration::from_secs(5));
        do_commit_bench::<KzgGridBenchBls12_381, _>(&mut g_commit, "kzg_bls12_381");
    }
    {
        let mut g_open = c.benchmark_group("grid_open");
        g_open.sample_size(10);
        do_open_bench::<KzgGridBenchBls12_381, _>(&mut g_open, "kzg_bls12_381");
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
            (size * size * B::bytes_per_elem()) as u64,
        ));
        let s = B::do_setup(size);
        let grid = B::rand_grid(size);
        let eg = B::extend_grid(&s, &grid);
        g.bench_with_input(BenchmarkId::new(suite_name, size), &size, |b, &_| {
            b.iter(|| B::make_opens(&s, &eg))
        });
    }
}

criterion_group!(grid_benches, grid_bench);
criterion_main!(grid_benches);
