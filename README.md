# Owasm

The standard libraries for building BandChain oracle scripts. Code in this package is split into 2 packages -- `vm` and `kit` (`ext`, and `oei`).

- `vm` - a library for building VM runtime
- `kit` - standard libraries for BandChain oracle scripts
    - `ext` - a library is helper package for writing the oracle scripts 
    - `oei` - a library containing functions for querying data from BandChain

## Coverage test
- `owasm-crypto` - cargo tarpaulin --out Html --output-dir reports/crypto --packages owasm-crypto
- `owasm-vm` - cargo tarpaulin --out Html --output-dir reports/vm --packages owasm-vm
