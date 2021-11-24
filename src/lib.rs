/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! # Remote Settings Client
//!
//! A library for fetching and synchronizing Remote Settings data.
//!
//! ## Example
//!
//! ```rust
//! # #[cfg(feature = "ring_verifier")] {
//!   use remote_settings_client::{Client, RingVerifier, client::net::ViaductClient};
//!   use viaduct::set_backend;
//!   use viaduct_reqwest::ReqwestBackend;
//!
//! # #[tokio::main]
//! # async fn main() {
//!   set_backend(&ReqwestBackend).unwrap();
//!
//!   let mut client = Client::builder()
//!     .bucket_name("main-preview")
//!     .http_client(Box::new(ViaductClient))
//!     .collection_name("search-config")
//!     .verifier(Box::new(RingVerifier {}))
//!     .build()
//!     .unwrap();
//!
//!   client.sync(None).await.unwrap();
//!
//!   match client.get().await {
//!     Ok(records) => println!("{:?}", records),
//!     Err(error) => println!("Error fetching/verifying records: {:?}", error),
//!   };
//! # }
//! }
//! ```
//!
//! See [`Client`] for more infos.

#[macro_use]
extern crate derive_builder;

pub mod client;

pub use client::Client;
pub use client::Collection;
pub use client::Record;
pub use client::SignatureError;
pub use client::Storage;
pub use client::StorageError;
pub use client::Verification;
pub use client::DEFAULT_BUCKET_NAME;
pub use client::DEFAULT_SERVER_URL;

#[cfg(feature = "ring_verifier")]
pub use crate::client::RingVerifier;

#[cfg(feature = "rc_crypto_verifier")]
pub use crate::client::RcCryptoVerifier;
