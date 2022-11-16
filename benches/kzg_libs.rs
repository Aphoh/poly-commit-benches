use criterion::{criterion_group, criterion_main, Criterion};

pub fn ark_bench(c: &mut Criterion) {

}

criterion_group!(benches, ark_bench);
criterion_main!(benches);

