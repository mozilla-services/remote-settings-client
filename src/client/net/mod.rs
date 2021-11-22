// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

mod dummy_client;
#[cfg(test)]
mod test_client;
#[cfg(feature = "viaduct_client")]
mod viaduct_client;

pub(crate) use dummy_client::DummyClient;
#[cfg(test)]
pub(crate) use test_client::{TestHttpClient, TestResponse};
#[cfg(feature = "viaduct_client")]
pub use viaduct_client::ViaductClient;

// Re-exported so that consumers don't need depend on Url.
pub use url::Url;

/// A convenience type to represent raw HTTP headers.
pub type Headers = HashMap<String, String>;

/// A response coming from an HTTP endpoint.
#[derive(Debug)]
pub struct Response {
    /// The HTTP status code of the response.
    pub status: u16,

    // The body of the response.
    pub body: Vec<u8>,

    // The headers of the response.
    pub headers: Headers,
}

impl Response {
    /// Whether or not the response code represents HTTP success.
    pub fn is_success(&self) -> bool {
        (200..=299).contains(&self.status)
    }
}

/// A description of a component used to perform an HTTP request.
pub trait Requester: std::fmt::Debug + Send + Sync {
    /// Perform an GET request toward the needed resource.
    ///
    /// # Arguments
    ///
    /// * `url` - the URL path to perform the HTTP GET on.
    fn get(&self, url: Url) -> Result<Response, ()>;
}
