use std::sync::Arc;

use wasmer::wasmparser::Operator;
use wasmer::{CompilerConfig, Singlepass, Store, Universal};
use wasmer_middlewares::Metering;

fn cost(operator: &Operator) -> u64 {
    // A flat fee for each operation
    // The target is 1 Teragas per millisecond
    match operator {
        Operator::Loop { .. } // loop headers are branch targets
        | Operator::End // block ends are branch targets
        | Operator::Else // "else" is the "end" of an if branch
        | Operator::Br { .. } // branch source
        | Operator::BrTable { .. } // branch source
        | Operator::BrIf { .. } // branch source
        | Operator::Call { .. } // function call - branch source
        | Operator::CallIndirect { .. } // function call - branch source
        | Operator::Return // end of function - branch source
        => { return 10_000_000 }
        _ => { return 2_500_000 }
    }
}

pub fn make_store() -> Store {
    let mut compiler = Singlepass::new();
    let metering = Arc::new(Metering::new(0, cost));
    compiler.push_middleware(metering);
    let engine = Universal::new(compiler).engine();
    Store::new(&engine)
}
