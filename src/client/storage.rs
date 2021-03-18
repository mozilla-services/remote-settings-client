/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod dummy_storage;
pub mod file_storage;
pub mod memory_storage;

use thiserror::Error;

/// A trait for giving a type a custom storage implementation
///
/// The `Storage` is used to store the collection content locally.
/// # How can I implement ```Storage```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification, Storage, StorageError};
/// # use remote_settings_client::client::Collection;
/// struct MyStore {}
///
/// impl Storage for MyStore {
///     fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
///         Ok(())
///     }
///
///     fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
///         Ok(Vec::new())
///     }
/// }
/// ```
pub trait Storage {
    /// Store a key, value pair.
    ///
    /// # Errors
    /// If an error occurs while storing, ```StorageError::Error``` is returned
    fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError>;

    /// Retrieve a value for a given key.
    ///
    /// # Errors
    /// If the key cannot be found, ```StorageError::ReadError``` is returned
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError>;
}

#[derive(Debug, PartialEq, Error)]
pub enum StorageError {
    #[error("cannot write to storage: {0}")]
    WriteError(String),
    #[error("cannot read from storage: {0}")]
    ReadError(String),
    #[error("key could not be found: {key}")]
    KeyNotFound { key: String },
}
