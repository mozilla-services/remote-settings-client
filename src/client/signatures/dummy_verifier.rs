/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{Collection, HashAlgorithm, SignatureError, Verification, VerificationAlgorithm};
use log::debug;

pub struct DummyVerifier {}

impl Verification for DummyVerifier {
    fn hash(&self, _: &[u8], _: HashAlgorithm) -> Result<Vec<u8>, SignatureError> {
        Ok(vec![]) // unreachable.
    }

    fn verify_message(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: VerificationAlgorithm,
    ) -> Result<(), SignatureError> {
        Ok(()) // unreachable.
    }

    fn verify(&self, _collection: &Collection, _: &str) -> Result<(), SignatureError> {
        debug!("default verifier implementation");
        Ok(())
    }
}
