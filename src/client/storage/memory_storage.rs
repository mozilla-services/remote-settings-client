use super::{Storage, StorageError};
use std::collections::HashMap;

#[derive(Default)]
pub struct MemoryStorage {
    mem: HashMap<String, Vec<u8>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            mem: HashMap::new(),
        }
    }
}

impl Storage for MemoryStorage {
    fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        self.mem.insert(key.to_string(), value);
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        match self.mem.get(key) {
            Some(v) => Ok(v.clone()),
            None => Err(StorageError::KeyNotFound {
                key: key.to_string(),
            }),
        }
    }
}
