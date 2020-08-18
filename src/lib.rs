//! # Remote-Settings Client
//!
//! A library for fetching Remote-Settings data

pub mod client;

pub use client::Client;
pub use client::Collection;
pub use client::SignatureError;
pub use client::Verification;
pub use client::RemoteStorage;
pub use client::RemoteStorageError;
pub use client::DEFAULT_BUCKET_NAME;
pub use client::DEFAULT_SERVER_URL;
