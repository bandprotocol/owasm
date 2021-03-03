use crate::core::error::Error;

use clru::CLruCache;
use cosmwasm_vm::Checksum;
use wasmer::{Instance, Module, Store};

#[derive(Debug, Default, Clone, Copy)]
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
