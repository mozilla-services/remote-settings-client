use super::{Storage, StorageError};

pub struct DummyStorage {}

impl Storage for DummyStorage {
    fn store(&mut self, _key: &str, _value: Vec<u8>) -> Result<(), StorageError> {
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::KeyNotFound {
            key: key.to_string(),
        })
    }
}
