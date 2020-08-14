
pub mod default_cache;

/// A trait for giving a type a custom cache storage implementation
///
/// Sometimes, you want to use your own cache implementation to store records retrieved from the remote-settings server
/// and we get it, we only ask for you to retrieve the records for us when we need them! 
/// # How can I implement ```RemoteStorage```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::client::Collection;
/// struct MyStore {}
///
/// impl RemoteStorage for MyStore {
///     fn store(&self, key: &str, record: serde_json::Value) -> Result<(), RemoteStorageError> {
///         Ok(())
///     }
/// 
///     fn retrieve(&self, key: &str, )
/// }
/// ```
pub trait RemoteStorage {

    /// Store key, value pair containing information about remote-settings records
    /// fetched from server
    ///
    /// # Errors
    /// If an error occurs while storing or retrieving, ```RemoteStorageError``` is returned
    fn store(&self, key: &str, value: &str) -> Result<(), RemoteStorageError>;

    /// Retrieve value mapping to the key
    /// 
    /// If key cannot be 
    fn retrieve(&self, key: &str) -> Result<String, RemoteStorageError>;
}

#[derive(Debug, PartialEq)]
pub enum RemoteStorageError {
    Error { name: String },
    DoesNotExistError { name: String }
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