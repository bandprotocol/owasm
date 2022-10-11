#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate owasm_vm;
use crate::owasm_vm::cache::*;
use crate::owasm_vm::error::Error;
use owasm_vm::vm::Querier;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;

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
            "--no-check",
        ])
        .output()
        .unwrap();
    let mut wasm = Vec::new();
    output_file.read_to_end(&mut wasm).unwrap();
    wasm
}

fn generate_wat(imported_function: String) -> String {
    let s = format!(
        r#"(module
            {}
            (func (;"execute": Resolves with result "beeb";))
            (memory (export "memory") 512)
            (data (i32.const 1048576) "beeb")
            (export "prepare" (func 1))
            (export "execute" (func 2)))
    "#,
        imported_function
    );
    return s;
}

fuzz_target!(|data: [u64; 30]| {
    let mut imported_wat = vec![];
    imported_wat.push((
        "get_span_size",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_span_size" (func (type 0)))
                (func
                    call 0
                    drop
                )"#
        ),
    ));
    imported_wat.push((
        "read_calldata",
        format!(
            r#"(type (func (param i64) (result i64)))
                (import "env" "read_calldata" (func (type 0)))
                (func
                    (i64.const {})
                    call 0
                    drop
                )"#,
            data[29],
        ),
    ));
    imported_wat.push((
        "set_return_data",
        format!(
            r#"(type (func (param i64 i64) (result)))
                (import "env" "set_return_data" (func (type 0)))
                (func
                    (i64.const {})
                    (i64.const {})
                    call 0
                )"#,
            data[28], data[29],
        ),
    ));
    imported_wat.push((
        "get_ask_count",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_ask_count" (func (type 0)))
                (func
                    call 0
                    drop
                )"#,
        ),
    ));
    imported_wat.push((
        "get_min_count",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_min_count" (func (type 0)))
                (func
                    call 0
                    drop
                )"#,
        ),
    ));
    imported_wat.push((
        "get_prepare_time",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_prepare_time" (func (type 0)))
                (func
                    call 0
                    drop
                )"#,
        ),
    ));
    imported_wat.push((
        "get_execute_time",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_execute_time" (func (type 0)))
                (func
                    call 0
                    drop
                )"#,
        ),
    ));
    imported_wat.push((
        "get_ans_count",
        format!(
            r#"(type (func (param) (result i64)))
                (import "env" "get_ans_count" (func (type 0)))
                (func
                    call 0
                    drop
                )"#,
        ),
    ));
    imported_wat.push((
        "ask_external_data",
        format!(
            r#"(type (func (param i64 i64 i64 i64) (result)))
                (import "env" "ask_external_data" (func (type 0)))
                (func
                    (i64.const {})
                    (i64.const {})
                    (i64.const {})
                    (i64.const {})
                    call 0
                )"#,
            data[26], data[27], data[28], data[29]
        ),
    ));
    imported_wat.push((
        "get_external_data_status",
        format!(
            r#"(type (func (param i64 i64) (result i64)))
                (import "env" "get_external_data_status" (func (type 0)))
                (func
                    (i64.const {})
                    (i64.const {})
                    call 0
                    drop
                )"#,
            data[28], data[29]
        ),
    ));
    imported_wat.push((
        "read_external_data",
        format!(
            r#"(type (func (param i64 i64 i64) (result i64)))
                (import "env" "read_external_data" (func (type 0)))
                (func
                    (i64.const {})
                    (i64.const {})
                    (i64.const {})
                    call 0
                    drop
                )"#,
            data[27], data[28], data[29]
        ),
    ));
    for (func, wat) in &imported_wat {
        println!("======================");
        println!("{:?}", func);
        let s = generate_wat(wat.clone());
        let wasm = wat2wasm(s);
        let code = owasm_vm::compile(&wasm).unwrap();
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let gas = owasm_vm::run(&mut cache, &code, u64::MAX, true, MockQuerier {});
        println!("{:?}", gas);
    }
});
