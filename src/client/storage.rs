
pub mod default_cache;

/// A trait for giving a type a custom cache storage implementation
///
/// Cache Storage API used to store records from server and retrieve when needed
/// # How can I implement ```RemoteStorage```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification, RemoteStorage, RemoteStorageError};
/// # use remote_settings_client::client::Collection;
/// struct MyStore {}
///
/// impl RemoteStorage for MyStore {
///     fn store(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RemoteStorageError> {
///         Ok(())
///     }
/// 
///     fn retrieve(&self, key: Vec<u8>) -> Result<Vec<u8>, RemoteStorageError> {
///         Ok(Vec::new())
///     }
/// }
/// ```
pub trait RemoteStorage {

    /// Store key, value pair containing information about remote-settings records
    /// fetched from server
    ///
    /// # Errors
    /// If an error occurs while storing or retrieving, ```RemoteStorageError``` is returned
    fn store(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RemoteStorageError>;

    /// Retrieve value mapping to the key
    /// 
    /// If key cannot be found, return RemoteStorageError::ReadError
    fn retrieve(&self, key: Vec<u8>) -> Result<Vec<u8>, RemoteStorageError>;
}

#[derive(Debug, PartialEq)]
pub enum RemoteStorageError {
    Error { name: String },
    ReadError { name: String }
}

impl From<std::io::Error> for RemoteStorageError {
    fn from(err: std::io::Error) -> Self {
        err.into()
    }
}

impl From<serde_json::error::Error> for RemoteStorageError {
    fn from(err: serde_json::error::Error) -> Self {
        err.into()
    }
}