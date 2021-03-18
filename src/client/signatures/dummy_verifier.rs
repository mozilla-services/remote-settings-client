/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{Collection, SignatureError, Verification};
use log::debug;

pub struct DummyVerifier {}

impl Verification for DummyVerifier {
    fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
        debug!("default verifier implementation");
        Ok(())
    }
}
