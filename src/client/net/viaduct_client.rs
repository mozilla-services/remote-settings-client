// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Headers, Method, Requester, Response};

use viaduct::{header_names, Request as ViaductRequest};

/// An HTTP client that uses [Viaduct](https://github.com/mozilla/application-services/tree/main/components/viaduct).
#[derive(Debug)]
pub struct ViaductClient;

impl Requester for ViaductClient {
    fn get(&self, url: url::Url) -> Result<Response, ()> {
        self.request_json(Method::GET, url, vec![], Headers::default())
    }

    fn request_json(
        &self,
        method: Method,
        url: url::Url,
        data: Vec<u8>,
        headers: Headers,
    ) -> Result<Response, ()> {
        let mut request = match method {
            Method::DELETE => ViaductRequest::delete(url),
            Method::GET => ViaductRequest::get(url),
            Method::PATCH => ViaductRequest::patch(url),
            Method::PUT => ViaductRequest::put(url),
            Method::POST => ViaductRequest::post(url),
        }
        // Set body.
        .body(data);
        // Set headers on request.
        request = request
            .header(header_names::CONTENT_TYPE, "application/json")
            .map_err(|_| ())?;
        for (key, value) in headers {
            request = request.header(key, value.as_str()).map_err(|_| ())?;
        }

        match request.send() {
            Err(e) => {
                log::error!(
                    "ViaductClient - unable to submit {:?} request. {:?}",
                    method,
                    e.to_string()
                );
                Err(())
            }
            Ok(response) => {
                let mut headers: Headers = Headers::new();
                for h in response.headers {
                    headers
                        .entry(h.name().to_string())
                        .or_insert_with(|| h.value().to_string());
                }

                Ok(Response {
                    status: response.status,
                    body: response.body,
                    headers,
                })
            }
        }
    }
}
