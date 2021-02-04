use crate::core::error::Error;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, RwLock};

use wasmer::{Instance, Memory, WasmerEnv};

pub trait Env {
    /// Returns the maximum span size value.
    fn get_span_size(&self) -> i64;
    /// Returns user calldata, or returns error from VM runner.
    fn get_calldata(&self) -> Result<Vec<u8>, Error>;
    /// Sends the desired return `data` to VM runner, or returns error from VM runner.
    fn set_return_data(&self, data: &[u8]) -> Result<(), Error>;
    /// Returns the current "ask count" value.
    fn get_ask_count(&self) -> i64;
    /// Returns the current "min count" value.
    fn get_min_count(&self) -> i64;
    /// Returns the current "ans count" value, or error from VM runner if called on wrong period.
    fn get_ans_count(&self) -> Result<i64, Error>;
    /// Issues a new external data request to VM runner, with the specified ids and calldata.
    fn ask_external_data(&self, eid: i64, did: i64, data: &[u8]) -> Result<(), Error>;
    /// Returns external data status for data id `eid` from validator index `vid`.
    fn get_external_data_status(&self, eid: i64, vid: i64) -> Result<i64, Error>;
    /// Returns data span with the data id `eid` from validator index `vid`.
    fn get_external_data(&self, eid: i64, vid: i64) -> Result<Vec<u8>, Error>;
}

/// A `VMLogic` encapsulates the runtime logic of Owasm scripts.
pub struct VMLogic<E>
where
    E: Env,
{
    pub env: E,         // The execution environment.
    pub gas_limit: u32, // Amount of gas allowed for total execution.
    pub gas_used: u32,  // Amount of gas used in this execution.
}

impl<E> VMLogic<E>
where
    E: Env,
{
    /// Creates a new `VMLogic` instance.
    pub fn new(env: E, gas: u32) -> Self {
        Self { env: env, gas_limit: gas, gas_used: 0 }
    }

    /// Consumes the given amount of gas. Return `OutOfGasError` error if run out of gas.
    pub fn consume_gas(&mut self, gas: u32) -> Result<(), Error> {
        self.gas_used = self.gas_used.saturating_add(gas);
        if self.out_of_gas() {
            Err(Error::OutOfGasError)
        } else {
            Ok(())
        }
    }

    pub fn out_of_gas(&self) -> bool {
        self.gas_used > self.gas_limit
    }
}

pub struct ContextData {
    /// A non-owning link to the wasmer instance
    wasmer_instance: Option<NonNull<Instance>>,
}

impl ContextData {
    pub fn new() -> Self {
        ContextData { wasmer_instance: None }
    }
}

#[derive(WasmerEnv)]
pub struct Environment<E>
where
    E: Env + 'static,
{
    vm: Arc<Mutex<VMLogic<E>>>,
    data: Arc<RwLock<ContextData>>,
}

impl<E: Env + 'static> Clone for Environment<E> {
    fn clone(&self) -> Self {
        Self { vm: Arc::clone(&self.vm), data: self.data.clone() }
    }
}
unsafe impl<E: Env> Send for Environment<E> {}
unsafe impl<E: Env> Sync for Environment<E> {}

impl<E> Environment<E>
where
    E: Env + 'static,
{
    pub fn new(e: E, gas: u32) -> Self {
        Self {
            vm: Arc::new(Mutex::new(VMLogic::<E>::new(e, gas))),
            data: Arc::new(RwLock::new(ContextData::new())),
        }
    }

    pub fn with_vm<C, R>(&self, callback: C) -> R
    where
        C: FnOnce(&VMLogic<E>) -> R,
    {
        callback(&self.vm.lock().unwrap())
    }

    pub fn with_mut_vm<C, R>(&self, callback: C) -> R
    where
        C: FnOnce(&mut VMLogic<E>) -> R,
    {
        callback(&mut self.vm.lock().unwrap())
    }

    /// Creates a back reference from a contact to its partent instance
    pub fn set_wasmer_instance(&self, instance: Option<NonNull<Instance>>) {
        let mut data = self.data.as_ref().write().unwrap();
        data.wasmer_instance = instance;
    }

    pub fn memory(&self) -> Result<Memory, Error> {
        let data = self.data.as_ref().read().unwrap();
        match data.wasmer_instance {
            Some(instance_ptr) => {
                let instance_ref = unsafe { instance_ptr.as_ref() };
                let mut memories: Vec<Memory> =
                    instance_ref.exports.iter().memories().map(|pair| pair.1.clone()).collect();

                match memories.pop() {
                    Some(m) => Ok(m),
                    None => Err(Error::MemoryOutOfBoundError),
                }
            }
            _ => Err(Error::BadMemorySectionError),
        }
    }
}
