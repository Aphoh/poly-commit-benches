# poly-commit-benches
This repo contains benchmarks for different KZG10 commitment strategies, as well as polynomial erasure encoding.
Running benches on `x86`, you can do
```
RUSTFLAGS="-C target-feature=+bmi2,+adx" cargo +nightly bench --features asm
```
which will use arkworks' finite field arithmetic.
on other platforms, just run 
```
cargo bench
```
