use crate::error::Error;
use crate::vm::{Environment, Querier};

use wasmer::{imports, Function, ImportObject, Store};

use owasm_crypto::ecvrf;

const IMPORTED_FUNCTION_GAS: u64 = 750_000_000;
const ECVRF_VERIFY_GAS: u64 = 7_500_000_000_000;

fn require_mem_range(max_range: usize, require_range: usize) -> Result<(), Error> {
    if max_range < require_range {
        return Err(Error::MemoryOutOfBoundError);
    }
    Ok(())
}

fn read_memory<Q>(env: &Environment<Q>, ptr: i64, len: i64) -> Result<Vec<u8>, Error>
where
    Q: Querier + 'static,
{
    let memory = env.memory()?;
    require_mem_range(memory.size().bytes().0, (ptr.saturating_add(len)) as usize)?;
    Ok(memory.view()[ptr as usize..(ptr.saturating_add(len)) as usize]
        .iter()
        .map(|cell| cell.get())
        .collect())
}

fn write_memory<Q>(env: &Environment<Q>, ptr: i64, data: Vec<u8>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let memory = env.memory()?;
    require_mem_range(memory.size().bytes().0, (ptr.saturating_add(data.len() as i64)) as usize)?;
    for (idx, byte) in data.iter().enumerate() {
        memory.view()[(ptr as usize).saturating_add(idx)].set(*byte);
    }
    Ok(data.len() as i64)
}

fn calculate_read_memory_gas(len: i64) -> u64 {
    1_000_000_000_u64.saturating_add((len as u64).saturating_mul(1_500_000))
}

fn calculate_write_memory_gas(len: usize) -> u64 {
    2_250_000_000_u64.saturating_add((len as u64).saturating_mul(30_000_000))
}

fn do_gas<Q>(env: &Environment<Q>, _gas: u32) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    Ok(())
}

fn do_get_span_size<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    Ok(env.with_querier_from_context(|querier| querier.get_span_size()))
}

fn do_read_calldata<Q>(env: &Environment<Q>, ptr: i64) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();
        let data = querier.get_calldata()?;

        if data.len() as i64 > span_size {
            return Err(Error::SpanTooSmallError);
        }

        env.decrease_gas_left(
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(data.len())),
        )?;
        write_memory(env, ptr, data)
    })
}

fn do_set_return_data<Q>(env: &Environment<Q>, ptr: i64, len: i64) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    if len < 0 {
        return Err(Error::DataLengthOutOfBound);
    }
    env.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();

        if len > span_size {
            return Err(Error::SpanTooSmallError);
        }
        env.decrease_gas_left(
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(len)),
        )?;

        let data: Vec<u8> = read_memory(env, ptr, len)?;
        querier.set_return_data(&data)
    })
}

fn do_get_ask_count<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    Ok(env.with_querier_from_context(|querier| querier.get_ask_count()))
}

fn do_get_min_count<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    Ok(env.with_querier_from_context(|querier| querier.get_min_count()))
}

fn do_get_prepare_time<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    Ok(env.with_querier_from_context(|querier| querier.get_prepare_time()))
}

fn do_get_execute_time<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    env.with_querier_from_context(|querier| querier.get_execute_time())
}

fn do_get_ans_count<Q>(env: &Environment<Q>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    env.with_querier_from_context(|querier| querier.get_ans_count())
}

fn do_ask_external_data<Q>(
    env: &Environment<Q>,
    eid: i64,
    did: i64,
    ptr: i64,
    len: i64,
) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    if len < 0 {
        return Err(Error::DataLengthOutOfBound);
    }
    env.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();

        if len > span_size {
            return Err(Error::SpanTooSmallError);
        }
        env.decrease_gas_left(
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(len)),
        )?;

        let data: Vec<u8> = read_memory(env, ptr, len)?;
        querier.ask_external_data(eid, did, &data)
    })
}

fn do_get_external_data_status<Q>(env: &Environment<Q>, eid: i64, vid: i64) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.decrease_gas_left(IMPORTED_FUNCTION_GAS)?;
    env.with_querier_from_context(|querier| querier.get_external_data_status(eid, vid))
}

fn do_read_external_data<Q>(
    env: &Environment<Q>,
    eid: i64,
    vid: i64,
    ptr: i64,
) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    env.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();
        let data = querier.get_external_data(eid, vid)?;

        if data.len() as i64 > span_size {
            return Err(Error::SpanTooSmallError);
        }

        env.decrease_gas_left(
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(data.len())),
        )?;
        write_memory(env, ptr, data)
    })
}

fn do_ecvrf_verify<Q>(
    env: &Environment<Q>,
    y_ptr: i64,
    y_len: i64,
    pi_ptr: i64,
    pi_len: i64,
    alpha_ptr: i64,
    alpha_len: i64,
) -> Result<u32, Error>
where
    Q: Querier + 'static,
{
    // consume gas relatively to the function running time (~7.5ms)
    env.decrease_gas_left(ECVRF_VERIFY_GAS)?;
    let y: Vec<u8> = read_memory(env, y_ptr, y_len)?;
    let pi: Vec<u8> = read_memory(env, pi_ptr, pi_len)?;
    let alpha: Vec<u8> = read_memory(env, alpha_ptr, alpha_len)?;
    Ok(ecvrf::ecvrf_verify(&y, &pi, &alpha) as u32)
}

pub fn create_import_object<Q>(store: &Store, owasm_env: Environment<Q>) -> ImportObject
where
    Q: Querier + 'static,
{
    imports! {
        "env" => {
            "gas" => Function::new_native_with_env(&store, owasm_env.clone(), do_gas),
            "get_span_size" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_span_size),
            "read_calldata" => Function::new_native_with_env(&store, owasm_env.clone(), do_read_calldata),
            "set_return_data" => Function::new_native_with_env(&store, owasm_env.clone(), do_set_return_data),
            "get_ask_count" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_ask_count),
            "get_min_count" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_min_count),
            "get_prepare_time" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_prepare_time),
            "get_execute_time" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_execute_time),
            "get_ans_count" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_ans_count),
            "ask_external_data" => Function::new_native_with_env(&store, owasm_env.clone(), do_ask_external_data),
            "get_external_data_status" => Function::new_native_with_env(&store, owasm_env.clone(), do_get_external_data_status),
            "read_external_data" => Function::new_native_with_env(&store, owasm_env.clone(), do_read_external_data),
            "ecvrf_verify" => Function::new_native_with_env(&store, owasm_env.clone(), do_ecvrf_verify),
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::cache::{Cache, CacheOptions};
    use crate::compile::compile;
    use crate::store::make_store;

    use std::io::{Read, Write};
    use std::process::Command;
    use std::ptr::NonNull;
    use tempfile::NamedTempFile;
    use wasmer::ExternType::Function;
    use wasmer::FunctionType;
    use wasmer::Instance;
    use wasmer::ValType::{I32, I64};

    pub struct MockQuerier {}

    impl Querier for MockQuerier {
        fn get_span_size(&self) -> i64 {
            300
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

    fn create_owasm_env() -> (Environment<MockQuerier>, Instance) {
        let wasm = wat2wasm(
            r#"(module
            (func
            )
            (func
              )
              (memory (export "memory") 100)
              (data (i32.const 1048576) "beeb") 
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let code = compile(&wasm).unwrap();

        let querier = MockQuerier {};
        let owasm_env = Environment::new(querier);
        let store = make_store();
        let import_object = create_import_object(&store, owasm_env.clone());
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let (instance, _) = cache.get_instance(&code, &store, &import_object).unwrap();

        return (owasm_env, instance);
    }

    #[test]
    fn test_import_object_function_type() {
        let querier = MockQuerier {};
        let owasm_env = Environment::new(querier);
        let store = make_store();
        assert_eq!(create_import_object(&store, owasm_env.clone()).externs_vec().len(), 13);

        assert_eq!(create_import_object(&store, owasm_env.clone()).externs_vec()[0].1, "gas");
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[0].2.ty(),
            Function(FunctionType::new([I32], []))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[1].1,
            "get_span_size"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[1].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[2].1,
            "read_calldata"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[2].2.ty(),
            Function(FunctionType::new([I64], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[3].1,
            "set_return_data"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[3].2.ty(),
            Function(FunctionType::new([I64, I64], []))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[4].1,
            "get_ask_count"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[4].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[5].1,
            "get_min_count"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[5].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[6].1,
            "get_prepare_time"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[6].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[7].1,
            "get_execute_time"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[7].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[8].1,
            "get_ans_count"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[8].2.ty(),
            Function(FunctionType::new([], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[9].1,
            "ask_external_data"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[9].2.ty(),
            Function(FunctionType::new([I64, I64, I64, I64], []))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[10].1,
            "get_external_data_status"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[10].2.ty(),
            Function(FunctionType::new([I64, I64], [I64]))
        );

        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[11].1,
            "read_external_data"
        );
        assert_eq!(
            create_import_object(&store, owasm_env.clone()).externs_vec()[11].2.ty(),
            Function(FunctionType::new([I64, I64, I64], [I64]))
        );
    }

    #[test]
    fn test_do_gas() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(Ok(()), do_gas(&owasm_env, 0));
    }

    #[test]
    fn test_do_get_span_size() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(300, do_get_span_size(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_read_calldata() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(1, do_read_calldata(&owasm_env, 0).unwrap());
    }

    #[test]
    fn test_do_set_return_data() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(Ok(()), do_set_return_data(&owasm_env, 0, 0))
    }

    #[test]
    fn test_do_get_ask_count() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(10, do_get_ask_count(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_get_min_count() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(8, do_get_min_count(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_get_prepare_time() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(100_000, do_get_prepare_time(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_get_execute_time() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(100_000, do_get_execute_time(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_get_ans_count() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(8, do_get_ans_count(&owasm_env).unwrap());
    }

    #[test]
    fn test_do_ask_external_data() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(Ok(()), do_ask_external_data(&owasm_env, 0, 0, 0, 0))
    }

    #[test]
    fn test_do_get_external_data_status() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(1, do_get_external_data_status(&owasm_env, 0, 0).unwrap());
    }

    #[test]
    fn test_do_read_external_data() {
        let gas_limit = 2_500_000_000_000;
        let (owasm_env, instance) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(gas_limit);

        assert_eq!(1, do_read_external_data(&owasm_env, 0, 0, 0).unwrap());
    }
}
