/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{Collection, SignatureError, Verification};
use crate::client::net::Requester;
use async_trait::async_trait;
use log::debug;

pub struct DummyVerifier {}

#[async_trait]
impl Verification for DummyVerifier {
    fn verify_nist384p_chain(
        &self,
        _: u64,
        _: &[u8],
        _: &str,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> Result<(), SignatureError> {
        Ok(()) // unreachable.
    }

    async fn verify(
        &self,
        _requester: &Box<dyn Requester + 'static>,
        _collection: &Collection,
        _: &str,
    ) -> Result<(), SignatureError> {
        debug!("default verifier implementation");
        Ok(())
    }

    fn verify_sha256_hash(&self, _content: &[u8], _expected: &[u8]) -> Result<(), SignatureError> {
        debug!("default verifier implementation");
        Ok(())
    }
}
