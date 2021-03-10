use crate::core::error::Error;

use clru::CLruCache;
use cosmwasm_vm::Checksum;
use wasmer::{Instance, Module, Store};

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Stats {
    pub hits: u32,
    pub misses: u32,
}

impl Stats {
    pub fn new() -> Self {
        Self { hits: 0, misses: 0 }
    }
}

/// An in-memory module cache
pub struct InMemoryCache {
    modules: CLruCache<Checksum, Module>,
}

impl InMemoryCache {
    pub fn new(max_entries: u32) -> Self {
        InMemoryCache { modules: CLruCache::new(max_entries as usize) }
    }

    pub fn store(&mut self, checksum: &Checksum, module: Module) -> Option<Module> {
        self.modules.put(*checksum, module)
    }

    /// Looks up a module in the cache and creates a new module
    pub fn load(&mut self, checksum: &Checksum) -> Option<Module> {
        self.modules.get(checksum).map(|m| m.clone())
    }
}

#[derive(Clone, Debug)]
pub struct CacheOptions {
    pub cache_size: u32,
}

pub struct Cache {
    memory_cache: InMemoryCache,
    stats: Stats,
}

impl Cache {
    pub fn new(options: CacheOptions) -> Self {
        let CacheOptions { cache_size } = options;

        Self { memory_cache: InMemoryCache::new(cache_size), stats: Stats::new() }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn get_instance(
        &mut self,
        wasm: &[u8],
        store: &Store,
        import_object: &wasmer::ImportObject,
    ) -> Result<wasmer::Instance, Error> {
        let checksum = Checksum::generate(wasm);

        // lookup cache
        if let Some(module) = self.memory_cache.load(&checksum) {
            self.stats.hits += 1;
            return Ok(Instance::new(&module, &import_object).unwrap());
        }
        self.stats.misses += 1;

        // recompile
        let module = Module::new(store, &wasm).map_err(|_| Error::InstantiationError)?;
        let instance =
            Instance::new(&module, &import_object).map_err(|_| Error::InstantiationError)?;

        self.memory_cache.store(&checksum, module);

        Ok(instance)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::NamedTempFile;
    use wasmer::{imports, Singlepass, Store, JIT};

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

    fn get_instance_without_err(cache: &mut Cache, wasm: &[u8]) -> wasmer::Instance {
        let compiler = Singlepass::new();
        let store = Store::new(&JIT::new(compiler).engine());
        let import_object = imports! {};

        match cache.get_instance(&wasm, &store, &import_object) {
            Ok(instance) => instance,
            Err(e) => panic!(e),
        }
    }

    #[test]
    fn test_catch() {
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );

        let instance1 = get_instance_without_err(&mut cache, &wasm);
        assert_eq!(&Stats { hits: 0, misses: 1 }, cache.stats());

        let instance2 = get_instance_without_err(&mut cache, &wasm);
        assert_eq!(&Stats { hits: 1, misses: 1 }, cache.stats());

        let ser1 = match instance1.module().serialize() {
            Ok(r) => r,
            Err(e) => panic!(e),
        };

        let ser2 = match instance2.module().serialize() {
            Ok(r) => r,
            Err(e) => panic!(e),
        };

        assert_eq!(ser1, ser2);
    }

    #[test]
    fn test_lru_catch() {
        let mut cache = Cache::new(CacheOptions { cache_size: 2 });
        let wasm1 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo (export "foo"))
              )"#,
        );

        let wasm2 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo2 (export "foo2"))
              )"#,
        );

        let wasm3 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo3 (export "foo3"))
              )"#,
        );

        // miss [_ _] => [1 _]
        get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(&Stats { hits: 0, misses: 1 }, cache.stats());

        // miss [1 _] => [2 1]
        get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(&Stats { hits: 0, misses: 2 }, cache.stats());

        // miss [2 1] => [3 2]
        get_instance_without_err(&mut cache, &wasm3);
        assert_eq!(&Stats { hits: 0, misses: 3 }, cache.stats());

        // hit [3 2] => [2 3]
        get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(&Stats { hits: 1, misses: 3 }, cache.stats());

        // miss [2 3] => [1 2]
        get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(&Stats { hits: 1, misses: 4 }, cache.stats());

        // hit [1 2] => [2 1]
        get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(&Stats { hits: 2, misses: 4 }, cache.stats());

        // miss [2 1] => [3 2]
        get_instance_without_err(&mut cache, &wasm3);
        assert_eq!(&Stats { hits: 2, misses: 5 }, cache.stats());
    }
}
