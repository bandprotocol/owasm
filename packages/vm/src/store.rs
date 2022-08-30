use std::sync::Arc;

use wasmer::{Singlepass, Store, Universal, wasmparser::Operator, CompilerConfig};
use wasmer_middlewares::Metering;

fn cost(_operator: &Operator) -> u64 {
    // A flat fee for each operation
    1
}

pub fn make_store() -> Store {
    let mut compiler = Singlepass::new();
    let metering = Arc::new(Metering::new(0, cost));
    compiler.push_middleware(metering);
    let engine = Universal::new(compiler).engine();
    Store::new(&engine)
}
