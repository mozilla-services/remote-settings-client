use {
    super::{Storage, StorageError},
    log::{debug, info},
    std::fs::OpenOptions,
    std::io::prelude::*,
    std::path::Path,
};

pub struct FileStorage {}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        err.into()
    }
}

impl Storage for FileStorage {
    fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        let file_name = &format!("{}.bin", key);
        let path = Path::new(file_name);
        debug!("Read from {:?}", path);

        match OpenOptions::new().write(true).create(true).open(path) {
            Err(err) => {
                info!("Couldn't open or create {}: {}", path.display(), err);
                return Err(StorageError::Error {
                    name: err.to_string(),
                });
            }
            Ok(mut file) => {
                file.write_all(&value)?;
                return Ok(());
            }
        };
    }

    fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let file_name = &format!("{}.bin", key);
        let path = Path::new(file_name);
        debug!("Read from {:?}", path);

        let mut file = match OpenOptions::new().read(true).write(false).open(path) {
            Ok(file) => file,
            Err(err) => {
                info!("Couldn't open {:?}: {}", path, err);
                return Ok(None);
            }
        };

        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(err) => {
                info!("Couldn't read {:?}: {}", path, err);
                return Ok(None);
            }
            Ok(_) => info!("{:?} contains {} bytes", path, s.len()),
        };

        Ok(Some(s.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{FileStorage, Storage};
    use env_logger;
    use log::error;
    use std::fs::remove_file;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn cleanup(file_path: &str) {
        remove_file(&file_path).or_else(|err| error!("Error removing file : {}", err));
    }

    #[test]
    fn test_store_key_value_with_no_file_present() {
        init();

        let mut storage = FileStorage {};

        storage
            .store("test", "some value".as_bytes().to_vec())
            .unwrap();

        let retrieve_result = storage.retrieve("test").unwrap();
        let value_bytes = retrieve_result.unwrap();
        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();

        assert_eq!(value_str, "some value");
        cleanup("test.bin");
    }

    #[test]
    fn test_store_overwrite_file() {
        init();

        let mut storage = FileStorage {};

        storage
            .store("test", "some value".as_bytes().to_vec())
            .unwrap();

        storage
            .store("test", "new value".as_bytes().to_vec())
            .unwrap();

        let retrieve_result = storage.retrieve("test").unwrap();
        let value_bytes = retrieve_result.unwrap();
        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();

        assert_eq!(value_str, "new value");
        cleanup("test.bin");
    }

    #[test]
    fn test_retrieve_cannot_find_file() {
        init();

        let storage = FileStorage {};

        assert!(storage.retrieve("test").unwrap().is_none());
    }
}
