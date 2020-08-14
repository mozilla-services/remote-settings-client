
use {
    super::{RemoteStorageError, RemoteStorage},
    log::{debug, info},
    std::path::Path,
    std::io::prelude::*,
    std::fs::{OpenOptions, remove_file},
};

pub struct DefaultCache {}

impl RemoteStorage for DefaultCache {
    fn store(&self, key: &str, value: &str) -> Result<(), RemoteStorageError> {
        debug!("default cache store key={},value={}", key, value);

        let file_name = &format!("{}.bin", key);
        let path = Path::new(file_name);
        let display = path.display();

        match OpenOptions::new().write(true).create(true).open(path) {
            Err(why) => {
                info!("couldn't open or create {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            }
            Ok(mut file) => {
                file.write_all(value.as_bytes())?;
                return Ok(())
            },
        };
    }

    fn retrieve(&self, key: &str) -> Result<String, RemoteStorageError> {
        debug!("default cache retrieve key={}", key);

        let file_name = &format!("{}.bin", key);
        let path = Path::new(file_name);

        let display = path.display();

        let mut file = match OpenOptions::new().read(true).write(false).open(path) {
            Err(why) => {
                info!("couldn't open or create {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            },
            Ok(file) => file,
        };

        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(why) => {
                info!("couldn't read {}: {}", display, why);
                return Err(RemoteStorageError::DoesNotExistError {name: why.to_string()});
            },
            Ok(_) => info!("{} contains:\n{}", display, s),
        };

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultCache, RemoteStorage, RemoteStorageError};
    use env_logger;
    use std::fs::remove_file;
    
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn cleanup(file_path: &str) {
        remove_file(&file_path).unwrap();
    }

    #[test]
    fn test_store_key_value_with_no_file_present() {
        init();
        
        let default_cache = DefaultCache {};

        const VALUE: &str = "records";
        // store key, value pair into the cache
        default_cache.store("test", VALUE).unwrap();

        let value = default_cache.retrieve("test").unwrap();

        assert_eq!(value, VALUE);
        cleanup("test.bin");
    }

    #[test]
    fn test_store_overwrite_file() {
        init();
        
        let default_cache = DefaultCache {};

        const VALUE: &str = "records";
        // store key, value pair into the cache
        default_cache.store("test", VALUE).unwrap();

        default_cache.store("test", "new-records").unwrap();

        let value = default_cache.retrieve("test").unwrap();

        assert_eq!(value, "new-records");
        cleanup("test.bin");
    }

    #[test]
    fn test_retrieve_cannot_find_file() {
        init();
        
        let default_cache = DefaultCache {};

        assert!(default_cache.retrieve("test").is_err());
    }
}
