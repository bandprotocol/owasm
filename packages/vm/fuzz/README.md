# Install cargo-fuzz

```sh
cargo install cargo-fuzz
```

# Run Fuzz Test

```sh
cargo fuzz run fuzz_target_1 -- -runs=<number of run limit>
```

** Currently, can't run on MacOS because of Sanitizer issue
For details see https://github.com/google/sanitizers/issues/189
