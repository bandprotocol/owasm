use crate::cache::Cache;
use crate::vm::{self, Environment};

pub use crate::error::Error;
pub use std::ptr::NonNull;
use std::sync::Arc;
use wasmer::Universal;
use wasmer_middlewares::metering::{get_remaining_points, MeteringPoints};

use wasmer::Singlepass;

use wasmer::{imports, wasmparser::Operator, CompilerConfig, Function, Store};
use wasmer_middlewares::Metering;

// use owasm_crypto::ecvrf;

fn require_mem_range(max_range: usize, require_range: usize) -> Result<(), Error> {
    if max_range < require_range {
        return Err(Error::MemoryOutOfBoundError);
    }
    Ok(())
}

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
            "gas" => Function::new_native_with_env(&store, owasm_env.clone(), |env: &Environment<E>, _gas: u32| {
                env.decrease_gas_left(1)
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
                    env.decrease_gas_left(span_size as u64)?;

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
                    env.decrease_gas_left(span_size as u64)?;

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
                    env.decrease_gas_left(span_size as u64)?;

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
                    env.decrease_gas_left(span_size as u64)?;

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
    use crate::compile::compile;
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

    #[test]
    fn test_ask_count_gas_used() {
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i64 i64) (result)))
                (import "env" "ask_external_data" (func (type 0)))
                (func
                    (local $idx i32)

                    (i64.const 1)
                    (i64.const 1)
                    (i64.const 1048576)
                    (i64.const 4)                  
                    call 0

                    (local.set $idx (i32.const 0))
                    (block
                        (loop
                            (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                            (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
                        )
                    )
                )
                (func (;"execute": Resolves with result "beeb";))
                (memory (export "memory") 17)
                (data (i32.const 1048576) "beeb")              
                (export "prepare" (func 1))
                (export "execute" (func 2)))
            "#,
        );

        let code = compile(&wasm).unwrap();
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let env = MockEnv {};
        let gas_used = run(&mut cache, &code, 4294967290, true, env).unwrap();
        assert_eq!(gas_used, 830018 as u64);
    }
}
