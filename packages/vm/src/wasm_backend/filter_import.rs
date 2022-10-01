use loupe::MemoryUsage;
use std::collections::HashMap;
use std::sync::Mutex;
use wasmer::wasmparser::Operator;
use wasmer::{
    FunctionMiddleware, LocalFunctionIndex, MiddlewareError, MiddlewareReaderState,
    ModuleMiddleware,
};
use wasmer_types::ModuleInfo;

#[derive(Debug, MemoryUsage)]
#[non_exhaustive]
pub struct FilterImport {
    // the latter is number of parameters of the import
    omitted_imports: HashMap<String, u32>,
    import_indexes: Mutex<HashMap<u32, u32>>,
}

impl FilterImport {
    fn new(omitted_imports: HashMap<String, u32>) -> Self {
        Self { omitted_imports, import_indexes: Mutex::new(HashMap::new()) }
    }
}

impl Default for FilterImport {
    fn default() -> Self {
        Self::new(HashMap::from([(String::from("env.gas"), 1)]))
    }
}

impl ModuleMiddleware for FilterImport {
    /// Generates a `FunctionMiddleware` for a given function.
    fn generate_function_middleware(&self, _: LocalFunctionIndex) -> Box<dyn FunctionMiddleware> {
        Box::new(FunctionFilterImport {
            import_indexes: self.import_indexes.lock().unwrap().clone(),
        })
    }

    /// Transforms a `ModuleInfo` struct in-place. This is called before application on functions begins.
    fn transform_module_info(&self, module_info: &mut ModuleInfo) {
        let mut import_indexes = self.import_indexes.lock().unwrap();
        module_info.imports.iter().for_each(|(key, _value)| {
            if let Some(params) = self.omitted_imports.get(&format!("{}.{}", key.0, key.1)) {
                import_indexes.insert(key.2, *params);
            }
        });
    }
}

#[derive(Debug)]
#[non_exhaustive]
struct FunctionFilterImport {
    import_indexes: HashMap<u32, u32>,
}

impl FunctionMiddleware for FunctionFilterImport {
    fn feed<'a>(
        &mut self,
        operator: Operator<'a>,
        state: &mut MiddlewareReaderState<'a>,
    ) -> Result<(), MiddlewareError> {
        match operator {
            Operator::Call { function_index } => {
                if let Some(params) = self.import_indexes.get(&function_index) {
                    state.extend(&vec![Operator::Drop; *params as usize]);
                } else {
                    state.push_operator(operator);
                }
            }
            _ => {
                state.push_operator(operator);
            }
        }

        Ok(())
    }
}
