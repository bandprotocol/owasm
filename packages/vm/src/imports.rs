use wasmer::{imports, Function, ImportObject, Store};

use crate::{
    vm::{self, Environment},
    Error,
};

// use owasm_crypto::ecvrf;

fn require_mem_range(max_range: usize, require_range: usize) -> Result<(), Error> {
    if max_range < require_range {
        return Err(Error::MemoryOutOfBoundError);
    }
    Ok(())
}

pub fn create_import_object<E>(store: &Store, owasm_env: Environment<E>) -> ImportObject
where
    E: vm::Env + 'static,
{
    imports! {
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
    }
}
