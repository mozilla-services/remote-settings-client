use {
    super::{Storage, StorageError},
    log::{debug, error},
    std::fs::OpenOptions,
    std::io::prelude::*,
    std::path::{Path, PathBuf},
};

pub struct FileStorage {
    pub folder: String,
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        err.into()
    }
}

impl FileStorage {
    fn _pathfor(&self, key: &str) -> PathBuf {
        let slug = key
            .chars()
            .map(|c| match c {
                'a'..='z' => c,
                'A'..='Z' => c,
                '0'..='9' => c,
                '-' => c,
                '_' => c,
                _ => '+',
            })
            .collect::<String>();
        Path::new(&self.folder).join(format!("{}.bin", slug))
    }
}

impl Storage for FileStorage {
    fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        let path = self._pathfor(&key);
        match OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&path)
        {
            Err(err) => {
                error!("Couldn't open or create {:?}: {}", path, err);
                Err(StorageError::Error {
                    name: err.to_string(),
                })
            }
            Ok(mut file) => {
                file.write_all(&value)?;
                file.sync_all()?;
                debug!("Wrote {} ({} bytes) into {:?}", key, value.len(), path);
                Ok(())
            }
        }
    }

    fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self._pathfor(&key);
        let mut file = match OpenOptions::new().read(true).write(false).open(&path) {
            Ok(file) => file,
            Err(err) => {
                debug!("Couldn't open {:?}: {}", path, err);
                return Ok(None);
            }
        };

        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(err) => {
                error!("Couldn't read {:?}: {}", path, err);
                return Ok(None);
            }
            Ok(size) => debug!("Read {} ({} bytes) from {:?}", key, size, path),
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
        if remove_file(&file_path).is_err() {
            error!("Error removing file : {}", file_path);
        };
    }

    #[test]
    fn test_store_key_value_with_no_file_present() {
        init();

        let mut storage = FileStorage {
            folder: ".".to_string(),
        };
        cleanup("./store-key.bin");

        storage
            .store("store-key", "some value".as_bytes().to_vec())
            .unwrap();

        let retrieve_result = storage.retrieve("store-key").unwrap();
        let value_bytes = retrieve_result.unwrap();
        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();

        assert_eq!(value_str, "some value");
        cleanup("./store-key.bin");
    }

    #[test]
    fn test_store_overwrite_file() {
        init();

        let mut storage = FileStorage {
            folder: ".".to_string(),
        };

        storage
            .store("overwrite-key", "some value".as_bytes().to_vec())
            .unwrap();

        storage
            .store("overwrite-key", "new value".as_bytes().to_vec())
            .unwrap();

        let retrieve_result = storage.retrieve("overwrite-key").unwrap();
        let value_bytes = retrieve_result.unwrap();
        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();

        assert_eq!(value_str, "new value");
        cleanup("./overwrite-key.bin");
    }

    #[test]
    fn test_retrieve_cannot_find_file() {
        init();

        let storage = FileStorage {
            folder: ".".to_string(),
        };
        cleanup("./unknown-key.bin");

        assert!(storage.retrieve("unknown-key").unwrap().is_none());
    }

    #[test]
    fn test_store_dangerous_key() {
        init();

        let mut storage = FileStorage::default();
        cleanup("./etc+password.bin");
        cleanup("./a_bid+a-cid+Records.bin");

        storage
            .store("/etc/password", "some value".as_bytes().to_vec())
            .unwrap();

        remove_file("./+etc+password.bin").unwrap(); // Fails if file is missing.

        storage
            .store("a_bid/a-cid:Records", "some value".as_bytes().to_vec())
            .unwrap();

        remove_file("./a_bid+a-cid+Records.bin").unwrap(); // Fails if file is missing.
    }
}
