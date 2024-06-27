/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
pub mod net;
mod signatures;
mod storage;

use anyhow::{anyhow, Context};
use log::{debug, info};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    time::Duration,
};
use url::Url;

#[cfg(test)]
use mock_instant::global::Instant;

#[cfg(not(test))]
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use kinto_http::{
    delete_record, get_changeset, get_latest_change_timestamp, patch_collection, put_record,
    KintoError, KintoObject,
};
pub use signatures::{SignatureError, Verification};
pub use storage::{
    dummy_storage::DummyStorage, file_storage::FileStorage, memory_storage::MemoryStorage, Storage,
    StorageError,
};

#[cfg(feature = "ring_verifier")]
pub use crate::client::signatures::ring_verifier::RingVerifier;

#[cfg(feature = "rc_crypto_verifier")]
pub use crate::client::signatures::rc_crypto_verifier::RcCryptoVerifier;

use crate::client::signatures::dummy_verifier::DummyVerifier;

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";
pub const DEFAULT_SIGNER_NAME: &str = "remote-settings.content-signature.mozilla.org";
pub const PROD_CERT_ROOT_HASH: &str = "97:E8:BA:9C:F1:2F:B3:DE:53:CC:42:A4:E6:57:7E:D6:4D:F4:93:C2:47:B4:14:FE:A0:36:81:8D:38:23:56:0E";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("content signature could not be verified: {0}")]
    IntegrityError(#[from] SignatureError),
    #[error("storage I/O error: {0}")]
    StorageError(#[from] StorageError),
    #[error("API failure: {0}")]
    APIError(#[from] KintoError),
    #[error("server indicated client to backoff ({0} secs remaining)")]
    BackoffError(u64),
    #[error("the Kinto server is not compatible with the request: {0}")]
    CompatibilityError(anyhow::Error),
    #[error("attachment data was not in the expected format: {0}")]
    AttachmentMetadataError(anyhow::Error),
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct Record {
    value: Value,
    #[serde(skip)]
    attachment: Attachment,
}

#[derive(Debug, PartialEq)]
pub enum Attachment {
    Pending,
    None,
    Some(AttachmentMetadata),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AttachmentMetadata {
    pub hash: String,
    pub size: usize,
    pub filename: String,
    pub location: String,
    pub mimetype: String,
}

impl Default for Attachment {
    fn default() -> Self {
        Attachment::Pending
    }
}

impl<'a> From<&'a Attachment> for Option<&'a AttachmentMetadata> {
    fn from(val: &'a Attachment) -> Self {
        match val {
            Attachment::Pending => None,
            Attachment::None => None,
            Attachment::Some(m) => Some(m),
        }
    }
}

impl Clone for Record {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            attachment: Attachment::Pending,
        }
    }
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        // ignore attachment, since it is in theory fully determined by `self.value`.
        self.value == other.value
    }
}

impl Record {
    pub fn new(value: Value) -> Record {
        Record {
            value,
            attachment: Attachment::Pending,
        }
    }

    // Return the underlying [`serde_json::Value`].
    pub fn as_object(&self) -> &serde_json::Map<String, serde_json::Value> {
        // Record data is always an object.
        self.value.as_object().unwrap()
    }

    // Return the record id.
    pub fn id(&self) -> &str {
        // `id` field is always present as a string.
        self.value["id"].as_str().unwrap()
    }

    // Return the record timestamp.
    pub fn last_modified(&self) -> u64 {
        // `last_modified` field is always present as a uint.
        self.value["last_modified"].as_u64().unwrap()
    }

    // Return true if the record is a tombstone.
    pub fn deleted(&self) -> bool {
        match self.get("deleted") {
            Some(v) => v.as_bool().unwrap_or(false),
            None => false,
        }
    }

    // Return a field value.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.value.get(key)
    }

    /// Return the attachment metadata for this record, if any.
    ///
    /// Return values:
    ///
    /// * `Ok(Some(AttachmentMetadata))` - There is an attachment, and it was
    ///   successfully converted to the expected format.
    /// * `Ok(None)` - There is no attachment for this record
    /// * `Err(_)` - There is an attachment for this record, but it is not
    ///   of the expected format.
    ///
    /// The `AttachmentMetadata::Pending` state should never be returned.
    pub fn attachment_metadata(&mut self) -> Result<Option<&AttachmentMetadata>, ClientError> {
        if let Attachment::Pending = self.attachment {
            let maybe_attachment = self
                .value
                .as_object()
                .and_then(|obj| obj.get("attachment"))
                .map(|a| serde_json::from_value::<AttachmentMetadata>(a.clone()));

            match maybe_attachment {
                Some(Ok(meta)) => {
                    self.attachment = Attachment::Some(meta);
                }
                Some(Err(err)) => {
                    // serde_json::Error does not implement std::error::Error,
                    // weirdly, so convert it to a string.
                    return Err(ClientError::AttachmentMetadataError(anyhow!(
                        "Could not convert attachment to requested type: {}",
                        err
                    )));
                }
                None => {
                    self.attachment = Attachment::None;
                }
            }
        }

        debug_assert_ne!(self.attachment, Attachment::Pending);

        Ok((&self.attachment).into())
    }
}

impl<I> std::ops::Index<I> for Record
where
    I: serde_json::value::Index,
{
    type Output = serde_json::Value;
    fn index(&self, index: I) -> &serde_json::Value {
        static NULL: serde_json::Value = serde_json::Value::Null;
        index.index_into(&self.value).unwrap_or(&NULL)
    }
}

/// Representation of a collection on the server
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<Record>,
    pub timestamp: u64,
    pub signer: String,
}

/// Client to fetch Remote Settings data.
///
/// # Examples
/// Create a `Client` for the `cid` collection on the production server:
/// ```rust
/// # use remote_settings_client::Client;
/// # fn main() {
/// let client = Client::builder()
///   .collection_name("cid")
///   .build()
///   .unwrap();
/// # }
/// ```
/// Or for a specific server or bucket:
/// ```rust
/// # use remote_settings_client::Client;
/// # fn main() {
/// let client = Client::builder()
///   .server_url("https://settings-cdn.stage.mozaws.net/v1")
///   .bucket_name("main-preview")
///   .collection_name("cid")
///   .build()
///   .unwrap();
/// # }
/// ```
///
/// ## Signature verification
///
/// When no verifier is explicitly specified, a dummy verifier is used.
///
/// ### `ring`
///
/// With the `ring_verifier` feature, a signature verifier leveraging the [`ring` crate](https://crates.io/crates/ring).
/// ```rust
/// # #[cfg(feature = "ring_verifier")] {
/// # use remote_settings_client::Client;
/// use remote_settings_client::RingVerifier;
///
/// let client = Client::builder()
///   .collection_name("cid")
///   .verifier(Box::new(RingVerifier {}))
///   .build()
///   .unwrap();
/// # }
/// ```
///
/// ### `rc_crypto`
///
/// With the `rc_crypto` feature, a signature verifier leveraging the [`rc_crypto` crate](https://github.com/mozilla/application-services/tree/v128.0/components/support/rc_crypto).
/// ```rust
/// # #[cfg(feature = "rc_crypto_verifier")] {
/// # use remote_settings_client::Client;
/// use remote_settings_client::RcCryptoVerifier;
///
/// let client = Client::builder()
///   .collection_name("cid")
///   .verifier(Box::new(RcCryptoVerifier {}))
///   .build()
///   .unwrap();
/// # }
/// ```
/// In order to use it, the NSS library must be available.
/// ```text
/// export NSS_DIR=/path/to/nss
/// export NSS_STATIC=1
///
/// cargo build --features=rc_crypto_verifier
/// ```
/// See [detailed NSS installation instructions](https://github.com/mozilla-services/remote-settings-client/blob/747e881/.circleci/config.yml#L25-L46).
///
/// ### Custom
/// See [`Verification`] for implementing a custom signature verifier.
///
/// ## Attachments
///
/// Attachments associated with records can be downloaded.
///
/// ```no_run
/// # use remote_settings_client::Client;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = Client::builder()
///   .collection_name("cid")
///   .build()
///   .unwrap();
///
/// // Attachment operations store cache data on records, so they need mutable references.
/// let mut records = client.get()?;
/// if let Some(attachment_metadata) = records[0].attachment_metadata()? {
///     println!("The attachment should be {} bytes long", attachment_metadata.size);
/// }
///
/// // The type returned can be anything that implement `From<Vec<u8>>`.
/// if let Some(attachment_body) = client.fetch_attachment::<Vec<u8>, _>(&mut records[0])? {
///     println!("Downloaded attachment with size {} bytes", attachment_body.len());
/// }
///
/// # Ok(())
/// # }
/// ```
///
/// Attachment metadata contain a hash of the expected content. The provided
/// verifier will be used to confirm that hash, and if it does not match a
/// verification error will be returned.
///
/// ## Write Operations
///
/// ```no_run
/// # use remote_settings_client::{Client, Record};
/// # use serde_json::json;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = Client::builder()
///   .authorization("Bearer abcdefghijkl")
///   .collection_name("cid")
///   .build()
///   .unwrap();
///
/// client
///   .store_record(Record::new(json!({
///     "id": "my-key",
///     "foo": "bar"
///   })))?;
///
/// // Request review from peers.
/// client.request_review("I made changes")?;
///
/// // Approve changes (publish).
/// let peer_reviewer = Client::builder()
///   .authorization("Bearer zyxwvutsrqp")
///   .collection_name("cid")
///   .build()
///   .unwrap();
///
/// peer_reviewer.approve_changes()?;
///
/// # Ok(())
/// # }
/// ```
///
#[derive(Builder, Debug)]
#[builder(pattern = "owned")] // No clone because of Box<dyn...>
pub struct Client {
    #[builder(setter(into), default = "DEFAULT_SERVER_URL.to_owned()")]
    server_url: String,
    #[builder(setter(into), default = "DEFAULT_BUCKET_NAME.to_owned()")]
    bucket_name: String,
    #[builder(setter(into))]
    collection_name: String,
    #[builder(setter(into), default = "DEFAULT_SIGNER_NAME.to_owned()")]
    signer_name: String,
    // Box<dyn Trait> is necessary since implementation of [`Verification`] can be of any size unknown at compile time
    #[builder(default = "Box::new(DummyVerifier {})")]
    verifier: Box<dyn Verification>,
    #[builder(default = "Box::new(DummyStorage {})")]
    storage: Box<dyn Storage>,
    #[builder(default = "true")]
    sync_if_empty: bool,
    #[builder(default = "true")]
    trust_local: bool,
    #[builder(private, default = "None")]
    backoff_until: Option<Instant>,
    #[builder(default = "PROD_CERT_ROOT_HASH.to_owned()")]
    cert_root_hash: String,
    #[builder(default = "Box::new(net::DummyClient)")]
    http_client: Box<dyn net::Requester + 'static>,
    #[builder(default = "None")]
    server_info: Option<Value>,
    #[builder(setter(into, strip_option), default = "None")]
    authorization: Option<String>,
}

impl Default for Client {
    fn default() -> Self {
        Client::builder().build().unwrap()
    }
}

impl std::fmt::Debug for Box<dyn Verification> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Box<dyn Verification>")
    }
}

impl std::fmt::Debug for Box<dyn Storage> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Box<dyn Storage>")
    }
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    fn _storage_key(&self) -> String {
        format!("{}/{}:collection", self.bucket_name, self.collection_name)
    }

    /// Return the records stored locally.
    ///
    /// # Examples
    /// ```rust
    /// # use remote_settings_client::Client;
    /// # use viaduct::set_backend;
    /// # pub use viaduct_reqwest::ReqwestBackend;
    /// # fn main() {
    /// # set_backend(&ReqwestBackend).unwrap();
    /// # let mut client = Client::builder().collection_name("url-classifier-skip-urls").build().unwrap();
    /// match client.get() {
    ///   Ok(records) => println!("{:?}", records),
    ///   Err(error) => println!("Error fetching/verifying records: {:?}", error)
    /// };
    /// # }
    /// ```
    ///
    /// # Behaviour
    /// * Return local data by default;
    /// * If local data is empty and if `sync_if_empty` is `true` (*default*),
    ///   then synchronize the local data with the server and return records, otherwise
    ///   return an error.
    ///
    /// Note: with the [`DummyStorage`], any call to `.get()` will trigger a synchronization.
    ///
    /// Note: with `sync_if_empty` as `false`, if `.sync()` is never called then `.get()` will
    /// always return an error.
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn get(&mut self) -> Result<Vec<Record>, ClientError> {
        let storage_key = self._storage_key();

        debug!("Retrieve from storage with key={:?}", storage_key);
        let read_result = self.storage.retrieve(&storage_key);

        match read_result {
            Ok(stored_bytes) => {
                // Deserialize content of storage and surface error if fails.
                let stored: Collection = serde_json::from_slice(&stored_bytes).map_err(|err| {
                    StorageError::ReadError(format!("cannot deserialize collection: {}", err))
                })?;
                // Verify signature of stored data (*optional*)
                if !self.trust_local {
                    debug!("Verify signature of local data.");
                    self.verifier.verify(
                        self.http_client.as_ref(),
                        &stored,
                        &self.cert_root_hash,
                    )?;
                }

                Ok(stored.records)
            }
            // If storage is empty, go on with sync() (*optional*)
            Err(StorageError::KeyNotFound { .. }) if self.sync_if_empty => {
                debug!("Synchronize data, without knowning which timestamp to expect.");
                let collection = self.sync(None)?;
                Ok(collection.records)
            }
            // Otherwise, surface the error.
            Err(err) => Err(err.into()),
        }
    }

    /// Synchronize the local storage with the content of the server for this collection.
    ///
    /// # Behaviour
    /// * If stored data is up-to-date and signature of local data valid, then return local content;
    /// * Otherwise fetch content from server, merge with local content, verify signature, and return records;
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn sync<T>(&mut self, expected: T) -> Result<Collection, ClientError>
    where
        T: Into<Option<u64>>,
    {
        self.check_sync_state()?;

        let storage_key = self._storage_key();

        debug!("Retrieve from storage with key={:?}", storage_key);
        let stored_bytes: Vec<u8> = self.storage.retrieve(&storage_key).unwrap_or_default();
        let stored: Option<Collection> = serde_json::from_slice(&stored_bytes).unwrap_or(None);

        let remote_timestamp = match expected.into() {
            Some(v) => v,
            None => {
                debug!("Obtain current timestamp.");
                get_latest_change_timestamp(
                    self.http_client.as_ref(),
                    &self.server_url,
                    &self.bucket_name,
                    &self.collection_name,
                )?
            }
        };

        if let Some(ref collection) = stored {
            let up_to_date = collection.timestamp == remote_timestamp;
            if up_to_date
                && self
                    .verifier
                    .verify(self.http_client.as_ref(), collection, &self.cert_root_hash)
                    .is_ok()
            {
                debug!("Local data is up-to-date and valid.");
                return Ok(stored.unwrap());
            }
        }

        info!("Local data is empty, outdated, or has been tampered. Fetch from server.");
        let (local_records, local_timestamp) = match stored {
            Some(c) => (c.records, Some(c.timestamp)),
            None => (Vec::new(), None),
        };

        let changeset = get_changeset(
            self.http_client.as_ref(),
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            remote_timestamp,
            local_timestamp,
        )?;

        // Keep in state that the server indicated the client
        // to backoff for a while.
        if let Some(backoff_secs) = changeset.backoff {
            self.backoff_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
        }

        debug!(
            "Apply {} changes to {} local records",
            changeset.changes.len(),
            local_records.len()
        );
        let merged = merge_changes(local_records, changeset.changes);

        let collection = Collection {
            bid: self.bucket_name.clone(),
            cid: self.collection_name.clone(),
            metadata: changeset.metadata,
            records: merged,
            timestamp: changeset.timestamp,
            signer: self.signer_name.clone(),
        };

        debug!("Verify signature after merge of changes with previous local data.");
        self.verifier
            .verify(self.http_client.as_ref(), &collection, &self.cert_root_hash)?;

        debug!("Store collection with key={:?}", storage_key);
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection)
            .map_err(|err| {
                StorageError::WriteError(format!("cannot serialize collection: {}", err))
            })?
            .into();
        self.storage.store(&storage_key, collection_bytes)?;

        Ok(collection)
    }

    fn check_sync_state(&mut self) -> Result<(), ClientError> {
        if let Some(until) = self.backoff_until {
            if Instant::now() < until {
                let remaining_secs = (until - Instant::now()).as_secs();
                return Err(ClientError::BackoffError(remaining_secs));
            }
            self.backoff_until = None;
        }
        Ok(())
    }

    pub fn server_info(&mut self) -> Result<&Value, ClientError> {
        if let Some(ref server_info) = self.server_info {
            Ok(server_info)
        } else {
            let info_url =
                Url::parse(&self.server_url).map_err(|err| ClientError::APIError(err.into()))?;

            let response = self
                .http_client
                .get(info_url)
                .map_err(|_err| ClientError::APIError(KintoError::HTTPBackendError()))?;

            if response.is_success() {
                let server_info = serde_json::from_slice(&response.body).map_err(|_err| {
                    ClientError::APIError(KintoError::UnexpectedResponse {
                        url: self.server_url.clone(),
                        response,
                    })
                })?;

                self.server_info = Some(server_info);
                Ok(self.server_info.as_ref().unwrap())
            } else {
                Err(ClientError::APIError(KintoError::UnexpectedResponse {
                    url: self.server_url.clone(),
                    response,
                }))
            }
        }
    }

    /// Download the attachment for a record.
    ///
    /// Return values:
    /// * Ok(Some(T)) - There is an attachment for the record and it was
    ///   successfully downloaded.
    /// * Err(_) - There is an attachment for the record, and there was a
    ///   problem while downloading it. This should be considered a temporary
    ///   error.
    /// * Ok(None) - There is no attachment for the record
    pub fn fetch_attachment<T, E>(&mut self, record: &mut Record) -> Result<Option<T>, ClientError>
    where
        T: TryFrom<Vec<u8>, Error = E>,
        E: 'static + Send + Sync + std::error::Error,
    {
        let metadata = match record.attachment_metadata()? {
            None => return Ok(None),
            Some(m) => m,
        };

        let key = format!(
            "attachment:{}/{}:{}",
            self.bucket_name, self.collection_name, metadata.hash
        );
        let bytes = match self.storage.retrieve(&key) {
            Ok(bytes) => Ok(bytes),

            Err(StorageError::KeyNotFound { .. }) => {
                // Download the attachment
                let url = {
                    let server_info = self.server_info()?;
                    match &server_info["capabilities"]["attachments"]["base_url"] {
                        Value::String(s) => {
                            let full_url = format!("{}{}", s, metadata.location);
                            Url::parse(&full_url)
                                .map_err(|err| ClientError::APIError(KintoError::URLError(err)))?
                        }
                        Value::Null => {
                            return Err(ClientError::CompatibilityError(anyhow!(
                                "server does not support attachments"
                            )));
                        }
                        _ => {
                            return Err(ClientError::CompatibilityError(anyhow!(
                                "server did not return a valid attachment base_url"
                            )));
                        }
                    }
                };

                let response = self
                    .http_client
                    .get(url.clone())
                    .map_err(|_| ClientError::APIError(KintoError::HTTPBackendError()))?;

                if response.is_success() {
                    Ok(response.body)
                } else {
                    return Err(ClientError::APIError(KintoError::UnexpectedResponse {
                        url: url.to_string(),
                        response,
                    }));
                }
            }

            Err(err) => Err(ClientError::StorageError(err)),
        }?;

        let hash_bytes = hex::decode(&metadata.hash)
            .context("decoded expected hash")
            .map_err(ClientError::AttachmentMetadataError)?;
        self.verifier
            .verify_sha256_hash(bytes.as_slice(), hash_bytes.as_slice())?;

        let rv = bytes
            .try_into()
            .context("parsing attachment to requested type")
            .map_err(ClientError::AttachmentMetadataError)?;
        Ok(Some(rv))
    }

    /// Store a record on the server.
    ///
    /// # Arguments
    ///
    /// * `record` - the record to store.
    pub fn store_record(&self, record: Record) -> Result<KintoObject, ClientError> {
        put_record(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            record.id(),
            &record.value,
        )
        .map_err(ClientError::APIError)
    }

    /// Delete a record from the server.
    ///
    /// # Arguments
    ///
    /// * `id` - the record id to delete.
    pub fn delete_record(&self, id: &str) -> Result<KintoObject, ClientError> {
        delete_record(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            id,
        )
        .map_err(ClientError::APIError)
    }

    /// Request review from configured reviewers.
    ///
    /// # Arguments
    ///
    /// * `message` - the editor message.
    pub fn request_review(&self, message: &str) -> Result<KintoObject, ClientError> {
        patch_collection(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            &json!({
                "status": "to-review",
                "last_editor_comment": message,
            }),
        )
        .map_err(ClientError::APIError)
    }

    /// Reject review.
    ///
    /// # Arguments
    ///
    /// * `message` - the editor message.
    pub fn reject_review(&self, message: &str) -> Result<KintoObject, ClientError> {
        patch_collection(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            &json!({
                "status": "in-progress",
                "last_editor_comment": message,
            }),
        )
        .map_err(ClientError::APIError)
    }

    /// Approve and publish changes.
    pub fn approve_changes(&self) -> Result<KintoObject, ClientError> {
        patch_collection(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            &json!({
                "status": "to-sign",
            }),
        )
        .map_err(ClientError::APIError)
    }

    /// Rollback pending changes.
    pub fn rollback_changes(&self) -> Result<KintoObject, ClientError> {
        patch_collection(
            self.http_client.as_ref(),
            &self.server_url,
            self.authorization.clone(),
            &self.bucket_name,
            &self.collection_name,
            &json!({
                "status": "to-rollback",
            }),
        )
        .map_err(ClientError::APIError)
    }
}

fn merge_changes(local_records: Vec<Record>, remote_changes: Vec<KintoObject>) -> Vec<Record> {
    // Merge changes by record id and delete tombstones.
    let mut local_by_id: HashMap<String, Record> = local_records
        .into_iter()
        .map(|record| (record.id().into(), record))
        .collect();
    for entry in remote_changes.into_iter().rev() {
        let change = Record::new(entry);
        let id = change.id();
        if change.deleted() {
            local_by_id.remove(id);
        } else {
            local_by_id.insert(id.into(), change);
        }
    }

    local_by_id.into_iter().map(|(_, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::net::{Headers, Method, Requester, TestHttpClient, TestResponse};
    use super::signatures::{SignatureError, Verification};
    use super::{
        Client, ClientError, Collection, DummyStorage, DummyVerifier, MemoryStorage, Record,
    };
    use crate::client::AttachmentMetadata;
    use env_logger;
    use httpmock::MockServer;
    use serde_json::json;
    use std::time::Duration;

    #[cfg(feature = "viaduct_client")]
    use viaduct::set_backend;

    #[cfg(feature = "viaduct_client")]
    use viaduct_reqwest::ReqwestBackend;

    #[cfg(feature = "viaduct_client")]
    use super::net::ViaductClient;

    #[cfg(feature = "ring_verifier")]
    pub use crate::client::signatures::ring_verifier::RingVerifier;

    struct VerifierWithInvalidSignatureError {}

    impl Verification for VerifierWithInvalidSignatureError {
        fn verify_nist384p_chain(
            &self,
            _: u64,
            _: &[u8],
            _: &str,
            _: &str,
            _: &[u8],
            _: &[u8],
        ) -> Result<(), SignatureError> {
            unreachable!()
        }

        fn verify(
            &self,
            _requester: &'_ (dyn Requester + 'static),
            _collection: &Collection,
            _: &str,
        ) -> Result<(), SignatureError> {
            Err(SignatureError::MismatchError(
                "fake invalid signature".to_owned(),
            ))
        }

        fn verify_sha256_hash(
            &self,
            _content: &[u8],
            _expected: &[u8],
        ) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    struct VerifierWithInvalidHashError {}

    impl Verification for VerifierWithInvalidHashError {
        fn verify_nist384p_chain(
            &self,
            _: u64,
            _: &[u8],
            _: &str,
            _: &str,
            _: &[u8],
            _: &[u8],
        ) -> Result<(), SignatureError> {
            unreachable!()
        }

        fn verify(
            &self,
            _requester: &'_ (dyn Requester + 'static),
            _collection: &Collection,
            _: &str,
        ) -> Result<(), SignatureError> {
            Ok(())
        }

        fn verify_sha256_hash(
            &self,
            _content: &[u8],
            _expected: &[u8],
        ) -> Result<(), SignatureError> {
            Err(SignatureError::MismatchError(
                "fake invalid hash".to_owned(),
            ))
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();

        #[cfg(feature = "viaduct_client")]
        let _ = set_backend(&ReqwestBackend);
    }

    #[test]
    fn test_fails_if_no_collection() {
        let err = Client::builder().build().unwrap_err();

        assert_eq!(err.to_string(), "`collection_name` must be initialized");
    }

    #[test]
    fn test_default_builder() {
        let client = Client::builder().collection_name("cid").build().unwrap();

        // Assert defaults for consumers.
        assert!(
            client.server_url.contains("services.mozilla.com"),
            "Unexpected server URL: {}",
            client.server_url
        );
        assert_eq!(client.bucket_name, "main");
        assert!(client.sync_if_empty);
        assert!(client.trust_local);
        // And Debug format
        assert_eq!(format!("{:?}", client), "Client { server_url: \"https://firefox.settings.services.mozilla.com/v1\", bucket_name: \"main\", collection_name: \"cid\", signer_name: \"remote-settings.content-signature.mozilla.org\", verifier: Box<dyn Verification>, storage: Box<dyn Storage>, sync_if_empty: true, trust_local: true, backoff_until: None, cert_root_hash: \"97:E8:BA:9C:F1:2F:B3:DE:53:CC:42:A4:E6:57:7E:D6:4D:F4:93:C2:47:B4:14:FE:A0:36:81:8D:38:23:56:0E\", http_client: DummyClient, server_info: None, authorization: None }");
    }

    #[test]
    fn test_get_works_with_dummy_storage() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset")
                .query_param("_expected", "0");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 555,
                        "bucket": "main",
                        "collection": "top-sites"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/top-sites/changeset")
                .query_param("_expected", "555");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 555,
                        "foo": "bar"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("top-sites")
            .storage(Box::new(DummyStorage {}))
            .verifier(Box::new(DummyVerifier {}))
            .build()
            .unwrap();

        let records = client.get().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert_hits(1);
        get_latest_change_mock.assert_hits(1);

        // Calling again will pull from network.
        let records_twice = client.get().unwrap();
        assert_eq!(records_twice.len(), 1);

        get_changeset_mock.assert_hits(2);
        get_latest_change_mock.assert_hits(2);

        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_get_with_empty_storage() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset")
                .query_param("_expected", "0");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 888,
                        "bucket": "main",
                        "collection": "pocket"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/pocket/changeset")
                .query_param("_expected", "888");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 888,
                        "foo": "bar"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("pocket")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(DummyVerifier {}))
            .build()
            .unwrap();

        let records = client.get().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert();
        get_latest_change_mock.assert();

        // Calling again won't pull from network.
        let records_twice = client.get().unwrap();
        assert_eq!(records_twice.len(), 1);

        get_changeset_mock.assert_hits(1);
        get_latest_change_mock.assert_hits(1);

        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_get_empty_storage_no_sync_if_empty() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("url-classifier-skip-urls")
            // Explicitly disable sync if empty.
            .sync_if_empty(false)
            .build()
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(
            err.to_string(),
            "storage I/O error: key could not be found: main/url-classifier-skip-urls:collection"
        );
    }

    #[test]
    fn test_get_bad_stored_data() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("cfr")
            .storage(Box::new(MemoryStorage::new()))
            .sync_if_empty(false)
            .build()
            .unwrap();

        client
            .storage
            .store("main/cfr:collection", b"abc".to_vec())
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(err.to_string(), "storage I/O error: cannot read from storage: cannot deserialize collection: expected value at line 1 column 1");
    }

    #[test]
    fn test_get_bad_stored_data_if_untrusted() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("search-config")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(VerifierWithInvalidSignatureError {}))
            .sync_if_empty(false)
            .trust_local(false)
            .build()
            .unwrap();

        let collection = Collection {
            bid: "main".to_owned(),
            cid: "search-config".to_owned(),
            metadata: json!({}),
            records: vec![Record::default()],
            timestamp: 42,
            signer: "some-name".to_owned(),
        };
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection).unwrap().into();
        client
            .storage
            .store("main/search-config:collection", collection_bytes)
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature mismatch: fake invalid signature"
        );
    }

    #[test]
    fn test_get_with_empty_records_list() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/regions/changeset")
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [],
                    "timestamp": 0
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("regions")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        client.sync(42).unwrap();

        assert_eq!(client.get().unwrap().len(), 0);

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_get_return_previously_synced_records() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/blocklist/changeset")
                .query_param("_expected", "123");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 123,
                        "foo": "bar"
                    }],
                    "timestamp": 123
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("blocklist")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        client.sync(123).unwrap();

        let records = client.get().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_pulls_current_timestamp_from_changes_endpoint_if_none() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 123,
                        "bucket": "main",
                        "collection": "fxmonitor"
                    }],
                    "timestamp": 42
                }"#,
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/fxmonitor/changeset")
                .query_param("_expected", "123");
            then.body(
                r#"{
                        "metadata": {},
                        "changes": [{
                            "id": "record-1",
                            "last_modified": 555,
                            "foo": "bar"
                        }],
                        "timestamp": 555
                    }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("fxmonitor")
            .build()
            .unwrap();

        client.sync(None).unwrap();

        get_changeset_mock.assert();
        get_latest_change_mock.assert();
        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_sync_uses_specified_expected_parameter() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/pioneers/changeset")
                .query_param("_expected", "13");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("pioneers")
            .build()
            .unwrap();

        client.sync(13).unwrap();

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_fails_with_unknown_collection() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 123,
                        "bucket": "main",
                        "collection": "fxmonitor"
                    }],
                    "timestamp": 42
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("url-classifier-skip-urls")
            .build()
            .unwrap();

        let err = client.sync(None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "API failure: unknown collection: main/url-classifier-skip-urls",
        );

        get_latest_change_mock.assert();
        get_latest_change_mock.delete();
    }

    #[test]
    #[cfg(feature = "ring_verifier")]
    fn test_sync_uses_x5u_from_metadata_to_verify_signatures() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {
                        "missing": "x5u"
                    },
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("onecrl")
            .verifier(Box::new(RingVerifier {}))
            .build()
            .unwrap();

        let err = client.sync(42).unwrap_err();

        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature payload has no x5u field"
        );

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_wraps_signature_errors() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/password-recipes/changeset")
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("password-recipes")
            .verifier(Box::new(VerifierWithInvalidSignatureError {}))
            .build()
            .unwrap();

        let err = client.sync(42).unwrap_err();
        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature mismatch: fake invalid signature"
        );

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_returns_collection_with_merged_changes() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock_1 = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_expected", "15");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 15
                    }, {
                        "id": "record-2",
                        "last_modified": 14,
                        "field": "before"
                    }, {
                        "id": "record-3",
                        "last_modified": 13
                    }],
                    "timestamp": 15
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("onecrl")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        let res = client.sync(15).unwrap();
        assert_eq!(res.records.len(), 3);

        get_changeset_mock_1.assert();
        get_changeset_mock_1.delete();

        let mut get_changeset_mock_2 = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_since", r#""15""#)
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 42,
                        "field": "after"
                    }, {
                        "id": "record-4",
                        "last_modified": 30
                    }, {
                        "id": "record-2",
                        "last_modified": 20,
                        "delete": true
                    }],
                    "timestamp": 42
                }"#,
            );
        });

        let res = client.sync(42).unwrap();
        assert_eq!(res.records.len(), 4);

        let record_1_idx = res
            .records
            .iter()
            .position(|r| r.id() == "record-1")
            .unwrap();
        let record_1 = &res.records[record_1_idx];
        assert_eq!(record_1["field"].as_str().unwrap(), "after");

        get_changeset_mock_2.assert();
        get_changeset_mock_2.delete();
    }

    #[test]
    fn test_record_fields() {
        let r = Record::new(json!({
            "id": "abc",
            "last_modified": 100,
            "foo": {"bar": 42},
            "pi": "3.14"
        }));

        assert_eq!(r.id(), "abc");
        assert_eq!(r.last_modified(), 100);
        assert!(!r.deleted());

        // Access fields by index
        assert_eq!(r["pi"].as_str(), Some("3.14"));
        assert_eq!(r["foo"]["bar"].as_u64(), Some(42));
        assert_eq!(r["bar"], serde_json::Value::Null);

        // Or by get() as optional value
        assert_eq!(r.get("bar"), None);
        assert_eq!(r.get("pi").unwrap().as_str(), Some("3.14"));
        assert_eq!(r.get("pi").unwrap().as_f64(), None);
        assert_eq!(r.get("foo").unwrap().get("bar").unwrap().as_u64(), Some(42));

        let r = Record::new(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": true
        }));
        assert!(r.deleted());

        let r = Record::new(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": "foo"
        }));
        assert!(!r.deleted());
    }

    #[test]
    fn test_backoff() {
        init();

        let mut response_headers = Headers::new();
        response_headers.insert("backoff".to_string(), "300".to_string());

        let fake_server = "https://www.example.com/v1";

        let test_responses: Vec<_> = [777, 888]
            .iter()
            .map(|&expected| TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/main/collections/nimbus/changeset?_expected={}",
                    fake_server, expected
                ),
                response_status: 200,
                response_body: json!(
                    {
                        "metadata": {},
                        "changes": [{
                            "id": "record-1",
                            "last_modified": expected
                        }],
                        "timestamp": expected
                    }
                )
                .to_string()
                .as_bytes()
                .to_vec(),
                response_headers: response_headers.clone(),
            })
            .collect();

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(test_responses));

        let mut client = Client::builder()
            .server_url(fake_server)
            .http_client(test_client)
            .collection_name("nimbus")
            .build()
            .unwrap();

        client.sync(777).unwrap();
        let second_sync = client.sync(888).unwrap_err();
        mock_instant::global::MockClock::advance(Duration::from_secs(600));
        client.sync(888).unwrap();

        assert!(matches!(second_sync, ClientError::BackoffError(_)));
    }

    #[test]
    fn test_attachment() {
        init();

        let fake_server = "https://www.example.com/v1";

        let test_responses = vec![
            // server metadata
            TestResponse {
                request_method: Method::GET,
                request_url: fake_server.to_string(),
                response_status: 200,
                response_body: json!({
                    "capabilities": {
                        "attachments": {
                            "base_url": format!("{}/attachments/", fake_server),
                        }
                    }
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // list of changed collections
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/monitor/collections/changes/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                        "bucket": "main",
                        "collection": "some-attachments"
                    }],
                    "timestamp": 0,
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // changes for this collection
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/main/collections/some-attachments/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {
                        "signature": {
                            "x5u": format!("{}/x5u", fake_server),
                        }
                    },
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                        "attachment": {
                            "hash": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
                            "size": 5,
                            "filename": "test-attachment.txt",
                            "location": "1",
                            "mimetype": "text/plain",
                        },
                    }],
                    "timestamp": 0,
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // fake signature
            TestResponse {
                request_method: Method::GET,
                request_url: format!("{}/x5u", fake_server),
                response_status: 200,
                response_body: vec![],
                response_headers: Headers::new(),
            },

            // The attachment
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/attachments/1",
                    fake_server
                ),
                response_status: 200,
                response_body: "test\n".as_bytes().to_vec(),
                response_headers: Headers::new(),
            },
        ];

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(test_responses));

        let mut client_builder = Client::builder()
            .server_url(fake_server)
            .http_client(test_client)
            .bucket_name("main")
            .collection_name("some-attachments");

        struct HashOnlyVerifier {
            inner: Box<dyn Verification>,
        }

        impl Verification for HashOnlyVerifier {
            fn verify_nist384p_chain(
                &self,
                _: u64,
                _: &[u8],
                _: &str,
                _: &str,
                _: &[u8],
                _: &[u8],
            ) -> Result<(), SignatureError> {
                Ok(())
            }

            fn verify_sha256_hash(
                &self,
                content: &[u8],
                expected: &[u8],
            ) -> Result<(), SignatureError> {
                self.inner.verify_sha256_hash(content, expected)
            }
        }

        // If available, set a verifier to check that the hash feature is working.
        #[allow(clippy::if_same_then_else)]
        if cfg!(feature = "ring") {
            #[cfg(feature = "ring")]
            {
                client_builder = client_builder.verifier(Box::new(HashOnlyVerifier {
                    inner: Box::new(crate::client::signatures::ring_verifier::RingVerifier {}),
                }));
            }
        } else if cfg!(feature = "rc_crypto") {
            #[cfg(feature = "rc_crypto")]
            {
                client_builder = client_builder.verifier(Box::new(HashOnlyVerifier {
                    inner: Box::new(
                        crate::client::signatures::rc_crypto_verifier::RcCryptoVerifier {},
                    ),
                }));
            }
        } else {
            client_builder = client_builder.verifier(Box::new(DummyVerifier {}));
        }

        let mut client = client_builder.build().unwrap();

        let mut records = client.get().unwrap();

        let attachment_metadata = records[0].attachment_metadata().unwrap();
        assert_eq!(
            attachment_metadata,
            Some(&AttachmentMetadata {
                hash: "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
                    .to_string(),
                size: 5,
                filename: "test-attachment.txt".to_string(),
                location: "1".to_string(),
                mimetype: "text/plain".to_string(),
            })
        );

        let attachment_body: Option<Vec<u8>> = client.fetch_attachment(&mut records[0]).unwrap();
        assert_eq!(attachment_body, Some("test\n".as_bytes().to_vec()));
    }

    #[test]
    fn test_no_attachment() {
        init();

        let fake_server = "https://www.example.com/v1";

        let test_responses = vec![
            // server metadata
            TestResponse {
                request_method: Method::GET,
                request_url: fake_server.to_string(),
                response_status: 200,
                response_body: json!({
                    "capabilities": {
                        "attachments": {
                            "base_url": format!("{}/attachments", fake_server),
                        }
                    }
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            },
            // list of changed collections
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/monitor/collections/changes/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                        "bucket": "main",
                        "collection": "some-attachments"
                    }],
                    "timestamp": 0,
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            },
            // changes for this collection
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/main/collections/some-attachments/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                    }],
                    "timestamp": 0,
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            },
        ];

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(test_responses));

        let mut client = Client::builder()
            .server_url(fake_server)
            .http_client(test_client)
            .bucket_name("main")
            .collection_name("some-attachments")
            .build()
            .unwrap();

        let mut records = client.get().unwrap();

        let attachment_metadata = records[0].attachment_metadata().unwrap();
        assert_eq!(attachment_metadata, None);

        let attachment_body: Option<Vec<u8>> = client.fetch_attachment(&mut records[0]).unwrap();
        assert_eq!(attachment_body, None);
    }

    #[test]
    fn test_attachment_bad_hash() {
        init();

        let fake_server = "https://www.example.com/v1";

        let test_responses = vec![
            // server metadata
            TestResponse {
                request_method: Method::GET,
                request_url: fake_server.to_string(),
                response_status: 200,
                response_body: json!({
                    "capabilities": {
                        "attachments": {
                            "base_url": format!("{}/attachments", fake_server),
                        }
                    }
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // list of changed collections
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/monitor/collections/changes/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                        "bucket": "main",
                        "collection": "some-attachments"
                    }],
                    "timestamp": 0,
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // changes for this collection
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/buckets/main/collections/some-attachments/changeset?_expected=0",
                    fake_server
                ),
                response_status: 200,
                response_body: json!({
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 0,
                        "attachment": {
                            "hash": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
                            "size": 5,
                            "filename": "test-attachment.txt",
                            "location": "/1",
                            "mimetype": "text/plain",
                        },
                    }],
                    "timestamp": 0,
                }).to_string().as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

            // The attachment
            TestResponse {
                request_method: Method::GET,
                request_url: format!(
                    "{}/attachments/1",
                    fake_server
                ),
                response_status: 200,
                response_body: "test\n".as_bytes().to_vec(),
                response_headers: Headers::new(),
            },

        ];

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(test_responses));

        let mut client = Client::builder()
            .server_url(fake_server)
            .http_client(test_client)
            .bucket_name("main")
            .collection_name("some-attachments")
            .verifier(Box::new(VerifierWithInvalidHashError {}))
            .build()
            .unwrap();

        let mut records = client.get().unwrap();
        let attachment_body = client.fetch_attachment::<Vec<u8>, _>(&mut records[0]);
        assert!(matches!(
            attachment_body,
            Err(ClientError::IntegrityError(_))
        ));
    }

    #[test]
    fn test_request_review() {
        init();

        let mock_server = MockServer::start();
        let patch_collection_mock = mock_server.mock(|when, then| {
            when.method("PATCH")
                .path("/buckets/main-workspace/collections/onecrl")
                .body_contains("\"status\":\"to-review\"")
                .body_contains("\"last_editor_comment\":\"Made changes\"")
                .header_exists("Authorization");
            then.status(200).body(
                r#"{
                    "data": {
                        "id": "cid",
                        "last_modified": 42,
                        "status": "to-review",
                        "last_editor_comment": "Made changes"
                    }
                }"#,
            );
        });

        let client = Client::builder()
            .server_url(mock_server.url(""))
            .http_client(Box::new(ViaductClient))
            .collection_name("onecrl")
            .authorization("Bearer m0z1ll4")
            .build()
            .unwrap();

        let res = client.request_review("Made changes").unwrap();
        assert_eq!(res["status"], "to-review");

        patch_collection_mock.assert();
    }
}
