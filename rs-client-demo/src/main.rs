/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use remote_settings_client::client::net::ViaductClient;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    env_logger::init();
    set_backend(&ReqwestBackend).unwrap();

    print!("Fetching records using RS client with default Verifier: ");

    let mut client = Client::builder()
        .http_client(Box::new(ViaductClient))
        .collection_name("url-classifier-skip-urls")
        .build()
        .unwrap();

    let records = client.get().await?;
    println!("Found {} records.", records.len());

    let url = "https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset?_expected=0";
    let response =
        tokio::task::spawn_blocking(move || Request::get(Url::parse(url).unwrap()).send().unwrap())
            .await
            .unwrap();
    let collections: KintoPluralResponse<LatestChangeEntry> = response.json().unwrap();

    for collection in &collections.changes {
        let cid = format!("{}/{}", collection.bucket, collection.collection);
        print!("Fetching records of {}: ", cid);

        // We use different signing chains depending on the bucket/collection.
        let signer_name = match collection.bucket.as_str() {
            "pinning" => "pinning-preload",
            "pinning-preview" => "pinning-preload",
            "security-state" => "onecrl",
            "security-state-preview" => "onecrl",
            "blocklists" => match collection.collection.as_str() {
                "certificates" => "onecrl",
                _ => "remote-settings",
            },
            _ => "remote-settings",
        };

        let temp_dir = std::env::temp_dir();
        let mut client = Client::builder()
            .http_client(Box::new(ViaductClient))
            .bucket_name(&collection.bucket)
            .collection_name(&collection.collection)
            .signer_name(format!("{}.content-signature.mozilla.org", signer_name))
            .storage(Box::new(FileStorage {
                folder: temp_dir,
                ..FileStorage::default()
            }))
            .verifier(Box::new(RingVerifier {}))
            .build()
            .unwrap();

        let records = client.get().await?;
        println!("Found {} records for {}.", records.len(), cid);
    }

    Ok(())
}
