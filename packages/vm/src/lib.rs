pub mod cache;
pub mod error;
pub mod vm;

use cache::Cache;
use vm::Environment;

pub use error::Error;
use parity_wasm::builder;
use parity_wasm::elements::{self, External, MemoryType, Module};
pub use std::ptr::NonNull;
use std::sync::Arc;
use wasmer::Universal;
use wasmer_middlewares::metering::{get_remaining_points, MeteringPoints};

use pwasm_utils::{self};

use wasmer::Singlepass;

use wasmer::{imports, wasmparser, wasmparser::Operator, CompilerConfig, Function, Store};
use wasmer_middlewares::Metering;

// use owasm_crypto::ecvrf;

// inspired by https://github.com/CosmWasm/cosmwasm/issues/81
// 512 pages = 32mb
static MEMORY_LIMIT: u32 = 512; // in pages
static MAX_STACK_HEIGHT: u32 = 16 * 1024; // 16Kib of stack.

static REQUIRED_EXPORTS: &[&str] = &["prepare", "execute"];
static SUPPORTED_IMPORTS: &[&str] = &[
    "env.get_span_size",
    "env.read_calldata",
    "env.set_return_data",
    "env.get_ask_count",
    "env.get_min_count",
    "env.get_prepare_time",
    "env.get_execute_time",
    "env.get_ans_count",
    "env.ask_external_data",
    "env.get_external_data_status",
    "env.read_external_data",
    "env.ecvrf_verify",
];

fn inject_memory(module: Module) -> Result<Module, Error> {
    let mut m = module;
    let section = match m.memory_section() {
        Some(section) => section,
        None => return Err(Error::BadMemorySectionError),
    };

    // The valid wasm has only the section length of memory.
    // We check the wasm is valid in the first step of compile fn.
    let memory = section.entries()[0];
    let limits = memory.limits();

    if limits.initial() > MEMORY_LIMIT {
        return Err(Error::BadMemorySectionError);
    }

    if limits.maximum() != None {
        return Err(Error::BadMemorySectionError);
    }

    // set max memory page = MEMORY_LIMIT
    let memory = MemoryType::new(limits.initial(), Some(MEMORY_LIMIT));

    // Memory existance already checked
    let entries = m.memory_section_mut().unwrap().entries_mut();
    entries.pop();
    entries.push(memory);

    Ok(builder::from_module(m).build())
}

fn inject_stack_height(module: Module) -> Result<Module, Error> {
    pwasm_utils::stack_height::inject_limiter(module, MAX_STACK_HEIGHT)
        .map_err(|_| Error::StackHeightInjectionError)
}

// fn inject_gas(module: Module) -> Result<Module, Error> {
//     // Simple gas rule. Every opcode and memory growth costs 1 gas.
//     let gas_rules = rules::Set::new(1, Default::default()).with_grow_cost(1);
//     pwasm_utils::inject_gas_counter(module, &gas_rules).map_err(|_| Error::GasCounterInjectionError)
// }

fn check_wasm_exports(module: &Module) -> Result<(), Error> {
    let available_exports: Vec<&str> = module.export_section().map_or(vec![], |export_section| {
        export_section.entries().iter().map(|entry| entry.field()).collect()
    });

    for required_export in REQUIRED_EXPORTS {
        if !available_exports.contains(required_export) {
            return Err(Error::InvalidExportsError);
        }
    }

    Ok(())
}

fn check_wasm_imports(module: &Module) -> Result<(), Error> {
    let required_imports =
        module.import_section().map_or(vec![], |import_section| import_section.entries().to_vec());

    for required_import in required_imports {
        let full_name = format!("{}.{}", required_import.module(), required_import.field());
        if !SUPPORTED_IMPORTS.contains(&full_name.as_str()) {
            return Err(Error::InvalidImportsError);
        }

        match required_import.external() {
            External::Function(_) => (), // ok
            _ => return Err(Error::InvalidImportsError),
        };
    }

    Ok(())
}

pub fn compile(code: &[u8]) -> Result<Vec<u8>, Error> {
    // Check that the given Wasm code is indeed a valid Wasm.
    wasmparser::validate(code).map_err(|_| Error::ValidationError)?;

    // Start the compiling chains.
    let module = elements::deserialize_buffer(code).map_err(|_| Error::DeserializationError)?;
    check_wasm_exports(&module)?;
    check_wasm_imports(&module)?;
    let module = inject_memory(module)?;
    let module = inject_stack_height(module)?;

    // Serialize the final Wasm code back to bytes.
    elements::serialize(module).map_err(|_| Error::SerializationError)
}

fn require_mem_range(max_range: usize, require_range: usize) -> Result<(), Error> {
    if max_range < require_range {
        return Err(Error::MemoryOutOfBoundError);
    }
    Ok(())
}

// fn get_from_mem<E: vm::Env>(env: &Environment<E>, ptr: i64, len: i64) -> Result<Vec<u8>, Error> {
//     let memory = env.memory()?;
//     require_mem_range(memory.size().bytes().0, (ptr + len) as usize)?;
//     Ok(memory.view()[ptr as usize..(ptr + len) as usize].iter().map(|cell| cell.get()).collect())
// }

fn cost(_operator: &Operator) -> u64 {
    // A flat fee for each operation
    1
}

pub fn run<E>(
    cache: &mut Cache,
    code: &[u8],
    gas: u64,
    is_prepare: bool,
    env: E,
) -> Result<u64, Error>
where
    E: vm::Env + 'static,
{
    let owasm_env = Environment::new(env);

    let mut compiler = Singlepass::new();
    let metering = Arc::new(Metering::new(0, cost));
    compiler.push_middleware(metering);
    let engine = Universal::new(compiler).engine();
    let store = Store::new(&engine);

    let import_object = imports! {
        "env" => {
            "gas" => Function::new_native_with_env(&store, owasm_env.clone(), |_env: &Environment<E>, _gas: u32| {
            }),
            "get_span_size" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_span_size()
                })
            }),
            "read_calldata" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, ptr: i64| {
                env.with_mut_vm(|vm| -> Result<i64, Error>{
                    let span_size = vm.env.get_span_size();
                    // consume gas equal size of span when read calldata
                    env.decrease_gas_left(span_size as u32)?;

                    let memory = env.memory()?;
                    require_mem_range(memory.size().bytes().0, (ptr + span_size) as usize)?;

                    let data = vm.env.get_calldata()?;

                    for (idx, byte) in data.iter().enumerate() {
                        memory.view()[ptr as usize + idx].set(*byte);
                    }

                    Ok(data.len() as i64)
                })
            }),
            "set_return_data" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, ptr: i64, len: i64| {
                env.with_mut_vm(|vm| {
                    let span_size = vm.env.get_span_size();

                    if len > span_size {
                        return Err(Error::SpanTooSmallError);
                    }

                    // consume gas equal size of span when save data to memory
                    env.decrease_gas_left(span_size as u32)?;

                    let memory = env.memory()?;
                    require_mem_range(memory.size().bytes().0, (ptr + span_size) as usize)?;

                    let data: Vec<u8> = memory.view()[ptr as usize..(ptr + len) as usize].iter().map(|cell| cell.get()).collect();
                    vm.env.set_return_data(&data)
                })
            }),
            "get_ask_count" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_ask_count()
                })
            }),
            "get_min_count" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_min_count()
                })
            }),
            "get_prepare_time" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_prepare_time()
                })
            }),
            "get_execute_time" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_execute_time()
                })
            }),
            "get_ans_count" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>| {
                env.with_vm(|vm| {
                    vm.env.get_ans_count()
                })
            }),
            "ask_external_data" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, eid: i64, did: i64, ptr: i64, len: i64| {
                env.with_mut_vm(|vm| {
                    let span_size = vm.env.get_span_size();

                    if len > span_size {
                        return Err(Error::SpanTooSmallError);
                    }

                    // consume gas equal size of span when write calldata for raw request
                    // vm.consume_gas(span_size  as u32)?;
                    env.decrease_gas_left(span_size as u32)?;

                    let memory = env.memory()?;
                    require_mem_range(memory.size().bytes().0, (ptr + span_size) as usize)?;

                    let data: Vec<u8> = memory.view()[ptr as usize..(ptr + len) as usize].iter().map(|cell| cell.get()).collect();
                    vm.env.ask_external_data(eid, did, &data)
                })
            }),
            "get_external_data_status" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, eid: i64, vid: i64| {
                env.with_vm(|vm| {
                    vm.env.get_external_data_status(eid, vid)
                })
            }),
            "read_external_data" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, eid: i64, vid: i64, ptr: i64| {
                env.with_mut_vm(|vm| -> Result<i64, Error>{
                    let span_size = vm.env.get_span_size();
                    // consume gas equal size of span when read data from report
                    env.decrease_gas_left(span_size as u32)?;

                    let memory = env.memory()?;
                    require_mem_range(memory.size().bytes().0, (ptr + span_size) as usize)?;

                    let data = vm.env.get_external_data(eid, vid)?;

                    for (idx, byte) in data.iter().enumerate() {
                        memory.view()[ptr as usize + idx].set(*byte);
                    }

                    Ok(data.len() as i64)
                })
            }),
            // "ecvrf_verify" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, y_ptr: i64, y_len: i64, pi_ptr: i64, pi_len: i64, alpha_ptr: i64, alpha_len: i64| {
            //     env.with_mut_vm(|vm| -> Result<u32, Error>{
            //         // consume gas relatively to the function running time (~12ms)
            //         vm.consume_gas(500000)?;
            //         env.decrease_gas_left(500000)?;

            //         let y: Vec<u8> = get_from_mem(env, y_ptr, y_len)?;
            //         let pi: Vec<u8>= get_from_mem(env, pi_ptr, pi_len)?;
            //         let alpha: Vec<u8> = get_from_mem(env, alpha_ptr, alpha_len)?;
            //         Ok(ecvrf::ecvrf_verify(&y, &pi, &alpha) as u32)
            //     })
            // }),
        },
    };

    let instance = cache.get_instance(code, &store, &import_object)?;
    let instance_ptr = NonNull::from(&instance);
    owasm_env.set_wasmer_instance(Some(instance_ptr));
    owasm_env.set_gas_left(gas);

    // get function and exec
    let entry = if is_prepare { "prepare" } else { "execute" };
    let function = instance
        .exports
        .get_function(entry)
        .unwrap()
        .native::<(), ()>()
        .map_err(|_| Error::BadEntrySignatureError)?;

    function.call().map_err(|runtime_err| {
        if let Ok(err) = runtime_err.downcast::<Error>() {
            return err.clone();
        }

        match get_remaining_points(&instance) {
            MeteringPoints::Remaining(_) => Error::RuntimeError,
            MeteringPoints::Exhausted => Error::OutOfGasError,
        }
    })?;

    match get_remaining_points(&instance) {
        MeteringPoints::Remaining(count) => Ok(gas.saturating_sub(count)),
        MeteringPoints::Exhausted => Err(Error::OutOfGasError),
    }
}

#[cfg(test)]
mod test {
    use crate::cache::CacheOptions;

    use super::*;
    use assert_matches::assert_matches;
    use parity_wasm::elements;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::NamedTempFile;

    pub struct MockEnv {}

    impl vm::Env for MockEnv {
        fn get_span_size(&self) -> i64 {
            30000
        }
        fn get_calldata(&self) -> Result<Vec<u8>, Error> {
            Ok(vec![1])
        }
        fn set_return_data(&self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn get_ask_count(&self) -> i64 {
            10
        }
        fn get_min_count(&self) -> i64 {
            8
        }
        fn get_prepare_time(&self) -> i64 {
            100_000
        }
        fn get_execute_time(&self) -> Result<i64, Error> {
            Ok(100_000)
        }
        fn get_ans_count(&self) -> Result<i64, Error> {
            Ok(8)
        }
        fn ask_external_data(&self, _: i64, _: i64, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn get_external_data_status(&self, _: i64, _: i64) -> Result<i64, Error> {
            Ok(1)
        }
        fn get_external_data(&self, _: i64, _: i64) -> Result<Vec<u8>, Error> {
            Ok(vec![1])
        }
    }

    fn wat2wasm(wat: impl AsRef<[u8]>) -> Vec<u8> {
        let mut input_file = NamedTempFile::new().unwrap();
        let mut output_file = NamedTempFile::new().unwrap();
        input_file.write_all(wat.as_ref()).unwrap();
        Command::new("wat2wasm")
            .args(&[
                input_file.path().to_str().unwrap(),
                "-o",
                output_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let mut wasm = Vec::new();
        output_file.read_to_end(&mut wasm).unwrap();
        wasm
    }

    fn get_module_from_wasm(code: &[u8]) -> Module {
        match elements::deserialize_buffer(code) {
            Ok(deserialized) => deserialized,
            Err(_) => panic!("Cannot deserialized"),
        }
    }

    #[test]
    fn test_inject_memory_ok() {
        let wasm = wat2wasm(r#"(module (memory 1))"#);
        let module = get_module_from_wasm(&wasm);
        assert_matches!(inject_memory(module), Ok(_));
    }

    #[test]
    fn test_compile() {
        let wasm = wat2wasm(
            r#"(module
            (type (func (param i64 i64 i32 i64) (result i64)))
            (import "env" "ask_external_data" (func (type 0)))
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 1000000000)))
                  )
                )
            )
            (func (;"execute": Resolves with result "beeb";)
            )
            (memory 17)
            (data (i32.const 1048576) "beeb") (;str = "beeb";)
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let code = compile(&wasm).unwrap();
        let expected = wat2wasm(
            r#"(module
                (type (;0;) (func (param i64 i64 i32 i64) (result i64)))
                (type (;1;) (func))
                (import "env" "ask_external_data" (func (;0;) (type 0)))
                (func (;1;) (type 1)
                  (local i32)
                  i32.const 0
                  local.set 0
                  block  ;; label = @1
                    loop  ;; label = @2
                      local.get 0
                      i32.const 1
                      i32.add
                      local.set 0
                      local.get 0
                      i32.const 1000000000
                      i32.lt_u
                      br_if 0 (;@2;)
                    end
                  end)
                (func (;2;) (type 1))
                (func (;3;) (type 1)
                  global.get 0
                  i32.const 3
                  i32.add
                  global.set 0
                  global.get 0
                  i32.const 16384
                  i32.gt_u
                  if  ;; label = @1
                    unreachable
                  end
                  call 1
                  global.get 0
                  i32.const 3
                  i32.sub
                  global.set 0)
                (memory (;0;) 17 512)
                (global (;0;) (mut i32) (i32.const 0))
                (export "prepare" (func 0))
                (export "execute" (func 3))
                (data (;0;) (i32.const 1048576) "beeb"))"#,
        );
        assert_eq!(code, expected);
    }

    #[test]
    fn test_simple_gas_used() {
        let wasm = wat2wasm(
            r#"(module
            (type (func (param i64 i64 i64 i64) (result)))
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
                  )
                )
            )
            (func (;"execute": Resolves with result "beeb";)
            )
            (memory 17)
            (data (i32.const 1048576) "beeb") (;str = "beeb";)
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let code = compile(&wasm).unwrap();
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let env = MockEnv {};
        let gas_used = run(&mut cache, &code, 4294967290, true, env).unwrap();
        assert_eq!(gas_used, 800013 as u64);
    }

    // #[test]
    // fn test_ask_count_gas_used() {
    //     let wasm = wat2wasm(
    //         r#"(module
    //             (type (func (param i64 i64 i64 i64)))
    //             (import "env" "ask_external_data" (func $ask_external_data (type 0)))
    //             (func
    //                 (local $idx i32)
    //                 (i64.const 1)
    //                 (i64.const 1)
    //                 (i64.const 1048576)
    //                 (i64.const 4)
    //                 call 0
    //               (local.set $idx (i32.const 0))
    //               (block
    //                   (loop
    //                     (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
    //                     (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
    //                   )
    //                 )
    //             )
    //             (func (;"execute": Resolves with result "beeb";)
    //             )
    //             (memory 17)
    //             (data (i32.const 1048576) "beeb") (;str = "beeb";)
    //             (export "prepare" (func 1))
    //             (export "execute" (func 2)))
    //       "#,
    //     );
    //     let code = compile(&wasm).unwrap();
    //     let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
    //     let env = MockEnv {};
    //     let gas_used = run(&mut cache, &code, 4294967290, true, env).unwrap();
    //     assert_eq!(gas_used, 1000015 as u32);
    // }

    #[test]
    fn test_inject_memory_no_memory() {
        let wasm = wat2wasm("(module)");
        let module = get_module_from_wasm(&wasm);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }
    #[test]
    fn test_inject_memory_two_memories() {
        // Generated manually because wat2wasm protects us from creating such Wasm:
        // "error: only one memory block allowed"
        let wasm = hex::decode(concat!(
            "0061736d", // magic bytes
            "01000000", // binary version (uint32)
            "05",       // section type (memory)
            "05",       // section length
            "02",       // number of memories
            "0009",     // element of type "resizable_limits", min=9, max=unset
            "0009",     // element of type "resizable_limits", min=9, max=unset
        ))
        .unwrap();
        let r = compile(&wasm);
        assert_eq!(r, Err(Error::ValidationError));
    }

    #[test]
    fn test_inject_memory_initial_size() {
        let wasm_ok = wat2wasm("(module (memory 512))");
        let module = get_module_from_wasm(&wasm_ok);
        assert_matches!(inject_memory(module), Ok(_));
        let wasm_too_big = wat2wasm("(module (memory 513))");
        let module = get_module_from_wasm(&wasm_too_big);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }

    #[test]
    fn test_inject_memory_maximum_size() {
        let wasm = wat2wasm("(module (memory 1 5))");
        let module = get_module_from_wasm(&wasm);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }

    #[test]
    fn test_inject_stack_height() {
        let wasm = wat2wasm(
            r#"(module
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 1000000000)))
                  )
                )
            )
            (func (;"execute": Resolves with result "beeb";)
            )
            (memory 17)
            (data (i32.const 1048576) "beeb") (;str = "beeb";)
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let module = inject_stack_height(get_module_from_wasm(&wasm)).unwrap();
        let wasm = elements::serialize(module).unwrap();
        let expected = wat2wasm(
            r#"(module
                (type (;0;) (func))
                (func (;0;) (type 0)
                  (local i32)
                  i32.const 0
                  local.set 0
                  block  ;; label = @1
                    loop  ;; label = @2
                      local.get 0
                      i32.const 1
                      i32.add
                      local.set 0
                      local.get 0
                      i32.const 1000000000
                      i32.lt_u
                      br_if 0 (;@2;)
                    end
                  end)
                (func (;1;) (type 0))
                (func (;2;) (type 0)
                  global.get 0
                  i32.const 3
                  i32.add
                  global.set 0
                  global.get 0
                  i32.const 16384
                  i32.gt_u
                  if  ;; label = @1
                    unreachable
                  end
                  call 0
                  global.get 0
                  i32.const 3
                  i32.sub
                  global.set 0)
                (memory (;0;) 17)
                (global (;0;) (mut i32) (i32.const 0))
                (export "prepare" (func 2))
                (export "execute" (func 1))
                (data (;0;) (i32.const 1048576) "beeb"))"#,
        );
        assert_eq!(wasm, expected);
    }

    #[test]
    fn test_check_wasm_imports() {
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i32 i64) (result i64)))
                (import "env" "beeb" (func (type 0))))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_imports(&module), Err(Error::InvalidImportsError));
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i32 i64) (result i64)))
                (import "env" "ask_external_data" (func  (type 0))))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_imports(&module), Ok(()));
    }

    #[test]
    fn test_check_wasm_exports() {
        let wasm = wat2wasm(
            r#"(module
            (func $execute (export "execute")))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_exports(&module), Err(Error::InvalidExportsError));
        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_exports(&module), Ok(()));
    }
}
