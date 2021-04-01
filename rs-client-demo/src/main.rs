/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use remote_settings_client::client::{FileStorage, RingVerifier};
use remote_settings_client::Client;
use serde::Deserialize;
pub use url::{ParseError, Url};
use viaduct::{set_backend, Request};
pub use viaduct_reqwest::ReqwestBackend;

#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    changes: Vec<T>,
}

#[derive(Deserialize, Debug)]
pub struct LatestChangeEntry {
    pub bucket: String,
    pub collection: String,
}

fn main() {
    env_logger::init();
    set_backend(&ReqwestBackend).unwrap();

    print!("Fetching records using RS client with default Verifier: ");

    let mut client = Client::builder()
        .collection_name("url-classifier-skip-urls")
        .build()
        .unwrap();

    match client.get() {
        Ok(records) => println!("{} records.", records.len()),
        Err(error) => println!("FAILED ({:?})", error),
    };

    let url = "https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset?_expected=0";
    let response = Request::get(Url::parse(&url).unwrap()).send().unwrap();
    let collections: KintoPluralResponse<LatestChangeEntry> = response.json().unwrap();

    let mut failed_fetch = Vec::new();

    for collection in &collections.changes {
        let cid = format!("{}/{}", collection.bucket, collection.collection);
        print!("Fetching records of {}: ", cid);

        let mut client = Client::builder()
            .bucket_name(&collection.bucket)
            .collection_name(&collection.collection)
            .storage(Box::new(FileStorage { folder: "/tmp".into(), ..FileStorage::default() }))
            .verifier(Box::new(RingVerifier {}))
            .build()
            .unwrap();

        match client.get() {
            Ok(records) => println!("{} records.", records.len()),
            Err(error) => {
                println!("FAILED ({:?})", error);
                failed_fetch.push(cid);
            }
        };
    }

    println!("The failed collections are {:?}", failed_fetch);
}
