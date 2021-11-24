// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Headers, Requester, Response};

use async_trait::async_trait;
use viaduct::Request as ViaductRequest;

/// An HTTP client that uses [Viaduct](https://github.com/mozilla/application-services/tree/main/components/viaduct).
#[derive(Debug)]
pub struct ViaductClient;

#[async_trait]
impl Requester for ViaductClient {
    async fn get(&self, url: url::Url) -> Result<Response, ()> {
        let res = tokio::task::spawn_blocking(move || match ViaductRequest::get(url).send() {
            Err(e) => {
                log::error!(
                    "ViaductClient - unable to submit GET request. {:?}",
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
        })
        .await;

        match res {
            Err(e) => {
                log::error!(
                    "ViaductClient - unable to spawn a blocking task. {:?}",
                    e.to_string()
                );

                Err(())
            }
            Ok(r) => r,
        }
    }
}
