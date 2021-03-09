//! # Remote Settings Client
//!
//! A library for fetching Remote Settings data.
//!
//! ```rust
//!   use remote_settings_client::Client;
//!   pub use viaduct::set_backend;
//!   pub use viaduct_reqwest::ReqwestBackend;
//!
//!   fn main() {
//!     set_backend(&ReqwestBackend).unwrap();
//!
//!     let client = Client::builder()
//!       .collection_name("search-config")
//!       .build();
//!
//!     match client.get() {
//!       Ok(records) => println!("{:?}", records),
//!       Err(error) => println!("Error fetching/verifying records: {:?}", error),
//!     };
//!   }
//! ```
//!
//! ## Configuration
//!
//! Server URL and bucket name can be configured:
//!
//! ```rust
//!   let client = Client::builder()
//!     .server_url("https://settings.stage.mozaws.net/v1")
//!     .bucket_name("main-preview")
//!     .collection_name("search-config")
//!     .build();
//! ```
//!
//! See [`ClientBuilder`] for more options.
//!
//! ## Signature verification
//!
//! Enable signature verification with the `ring_verifier` feature.
//!
//! | Feature         | Description                                |
//! |-----------------|--------------------------------------------|
//! | *default*       | No signature verification of data          |
//! | `ring_verifier` | Uses the `ring` crate to verify signatures |
//!
//! See [`traits.signatures.Verification`] for more options.
pub mod client;

pub use client::Client;
pub use client::Collection;
pub use client::SignatureError;
pub use client::Verification;

pub use client::DEFAULT_BUCKET_NAME;
pub use client::DEFAULT_SERVER_URL;
