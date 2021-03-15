/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use env_logger;
use remote_settings_client::{Client, Collection, SignatureError, Verification};
use remote_settings_client::client::FileStorage;
use serde::Deserialize;
pub use url::{ParseError, Url};
use viaduct::{set_backend, Request};
pub use viaduct_reqwest::ReqwestBackend;

struct CustomVerifier {}

#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    changes: Vec<T>,
}

#[derive(Deserialize, Debug)]
pub struct LatestChangeEntry {
    pub bucket: String,
    pub collection: String,
}

impl Verification for CustomVerifier {
    fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
        Ok(()) // everything is verified!
    }
}

fn main() {
    env_logger::init();
    set_backend(&ReqwestBackend).unwrap();

    print!("Fetching records using RS client with default Verifier: ");

    let mut client = Client::builder()
        .collection_name("url-classifier-skip-urls")
        .build();

    match client.get() {
        Ok(records) => println!("{} records.", records.len()),
        Err(error) => println!("FAILED ({:?})", error),
    };

    print!("Fetching records using RS client with custom Verifier: ");

    let mut client_with_custom_verifier = Client::builder()
        .collection_name("url-classifier-skip-urls")
        .verifier(Box::new(CustomVerifier {}))
        .build();

    match client_with_custom_verifier.get() {
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
            .storage(Box::new(FileStorage { folder: "/tmp" }))
            .build();

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
