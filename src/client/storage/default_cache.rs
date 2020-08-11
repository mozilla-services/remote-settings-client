
use {
    super::{RemoteStorageError, RemoteStorage},
    log::{debug, info},
    serde_json::Value,
    std::path::Path,
    std::io::prelude::*,
    std::fs::OpenOptions,
};

pub struct DefaultCache {}

impl RemoteStorage for DefaultCache {
    fn store(&self, key: &str, value: Value) -> Result<(), RemoteStorageError> {
        debug!("default cache store key={},value={}", key, value);

        let file_name = &format!("{}.txt", key);
        let path = Path::new(file_name);
        let display = path.display();

        // Open the path in read-only mode, returns `io::Result<File>`
        match OpenOptions::new().write(true).create(true).append(false).open(path) {
            Err(why) => {
                info!("couldn't open or create {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            }
            Ok(mut file) => {
                let content = match value.as_str() {
                    Some(val) => val.as_bytes(),
                    None => "".as_bytes(),
                };

                file.write_all(content)?;
                return Ok(())
            },
        };
    }

    fn retrieve(&self, key: &str) -> Result<Value, RemoteStorageError> {
        debug!("default cache retrieve key={}", key);

        let file_name = &format!("{}.txt", key);
        let path = Path::new(file_name);

        let display = path.display();

        let mut file = match OpenOptions::new().read(true).write(false).open(path) {
            Err(why) => {
                info!("couldn't open or create {}: {}", display, why);
                return Err(RemoteStorageError::Error { name: why.to_string() })
            },
            Ok(file) => file,
        };

        // Read the file contents into a string, returns `io::Result<usize>`
        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(why) => {
                info!("couldn't read {}: {}", display, why);
                return Err(RemoteStorageError::DoesNotExistError {name: why.to_string()});
            },
            Ok(_) => info!("{} contains:\n{}", display, s),
        };

        let value = serde_json::from_str(&s)?;
        Ok(value)
    }
}
