use super::{Storage, StorageError};

pub struct DummyStorage {}

impl Storage for DummyStorage {
    fn store(&mut self, _key: &str, _value: Vec<u8>) -> Result<(), StorageError> {
        Ok(())
    }

    fn retrieve(&self, _key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }
}
