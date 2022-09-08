use std::sync::Arc;

use wasmer::wasmparser::Operator;
use wasmer::{CompilerConfig, Singlepass, Store, Universal};
use wasmer_middlewares::Metering;

fn cost(_operator: &Operator) -> u64 {
    // A flat fee for each operation
    // The target is 1 Teragas per millisecond
    2_500_000
}

pub fn make_store() -> Store {
    let mut compiler = Singlepass::new();
    let metering = Arc::new(Metering::new(0, cost));
    compiler.push_middleware(metering);
    let engine = Universal::new(compiler).engine();
    Store::new(&engine)
}
