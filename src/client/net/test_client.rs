// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Headers, Requester, Response};

use async_trait::async_trait;

#[derive(Debug)]
pub(crate) struct TestResponse {
    pub request_url: String,
    pub response_status: u16,
    pub response_body: Vec<u8>,
    pub response_headers: Headers,
}

/// A dummy HTTP client to use in tests
#[derive(Debug)]
pub(crate) struct TestHttpClient {
    test_responses: Vec<TestResponse>,
}

impl TestHttpClient {
    pub fn new(test_responses: Vec<TestResponse>) -> TestHttpClient {
        Self { test_responses }
    }
}

#[async_trait]
impl Requester for TestHttpClient {
    async fn get(&self, url: url::Url) -> Result<Response, ()> {
        for r in &self.test_responses {
            // Only respond to the specific URL if we're told to.
            if url.to_string().eq(&r.request_url) {
                return Ok(Response {
                    status: r.response_status,
                    body: r.response_body.clone(),
                    headers: r.response_headers.clone(),
                });
            }
        }

        Ok(Response {
            status: 404,
            body: vec![],
            headers: Headers::new(),
        })
    }
}
