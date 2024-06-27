// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Headers, Method, Requester, Response};

/// A dummy HTTP client implementation that always errors.
#[derive(Debug)]
pub struct DummyClient;

impl Requester for DummyClient {
    fn get(&self, _url: url::Url) -> Result<Response, ()> {
        Err(())
    }

    fn request_json(
        &self,
        _method: Method,
        _url: url::Url,
        _data: Vec<u8>,
        _headers: Headers,
    ) -> Result<Response, ()> {
        Err(())
    }
}
