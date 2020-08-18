
use {
    super::{RemoteStorageError, RemoteStorage},
    log::{debug, info},
    std::path::Path,
    std::io::prelude::*,
    std::fs::OpenOptions
};

pub struct DefaultCache {}

impl From<std::string::FromUtf8Error> for RemoteStorageError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        err.into()
    }
}

impl RemoteStorage for DefaultCache {
    fn store(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RemoteStorageError> {
        debug!("default cache store key={:?},value={:?}", key, value);

        let file_name = &format!("{}.bin", String::from_utf8(key)?);
        let path = Path::new(file_name);
        let display = path.display();

        match OpenOptions::new().write(true).create(true).open(path) {
            Err(why) => {
                info!("couldn't open or create {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            }
            Ok(mut file) => {
                file.write_all(&value)?;
                return Ok(())
            },
        };
    }

    fn retrieve(&self, key: Vec<u8>) -> Result<Vec<u8>, RemoteStorageError> {
        debug!("default cache retrieve key={:?}", key);

        let file_name = &format!("{}.bin", String::from_utf8(key)?);
        let path = Path::new(file_name);

        let display = path.display();

        let mut file = match OpenOptions::new().read(true).write(false).open(path) {
            Err(why) => {
                info!("couldn't open {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            },
            Ok(file) => file,
        };

        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(why) => {
                info!("couldn't read {}: {}", display, why);
                return Err(RemoteStorageError::ReadError {name: why.to_string()});
            },
            Ok(_) => info!("{} contains:\n{}", display, s),
        };

        Ok(s.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultCache, RemoteStorage};
    use env_logger;
    use std::fs::remove_file;
    use log::error;
    
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn cleanup(file_path: &str) {
        match remove_file(&file_path) {
            Ok(_) => {},
            Err(err) => error!("error removing file : {}", err)
        }
    }

    #[test]
    fn test_store_key_value_with_no_file_present() {
        init();
        
        let mut default_cache = DefaultCache {};

        let key: Vec<u8> = "test".as_bytes().clone().to_vec();
        let value: Vec<u8> = "records".as_bytes().to_vec();
        // store key, value pair into the cache
        default_cache.store(key, value).unwrap();

        let value_bytes = default_cache.retrieve("test".as_bytes().to_vec()).unwrap();
        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();

        assert_eq!(value_str, "records");
        cleanup("test.bin");
    }

    #[test]
    fn test_store_overwrite_file() {
        init();
        
        let mut default_cache = DefaultCache {};

        let key: Vec<u8> = "test".as_bytes().to_vec();
        let value: Vec<u8> = "records".as_bytes().to_vec();
        // store key, value pair into the cache
        default_cache.store(key.clone(), value).unwrap();

        default_cache.store(key, "new-records".as_bytes().to_vec()).unwrap();

        let value_bytes = default_cache.retrieve("test".as_bytes().to_vec()).unwrap();

        let value_str = String::from_utf8(value_bytes.to_vec()).unwrap();
        assert_eq!(value_str, "new-records");
        cleanup("test.bin");
    }

    #[test]
    fn test_retrieve_cannot_find_file() {
        init();

        let key: Vec<u8> = "test".as_bytes().to_vec();
        let default_cache = DefaultCache {};

        assert!(default_cache.retrieve(key).is_err());
    }
}
