/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{Storage, StorageError};

pub struct DummyStorage {}

impl Storage for DummyStorage {
    fn store(&mut self, _key: &str, _value: Vec<u8>) -> Result<(), StorageError> {
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::KeyNotFound {
            key: key.to_string(),
        })
    }
}
