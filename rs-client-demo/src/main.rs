/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use remote_settings_client::client::net::ViaductClient;
use remote_settings_client::client::{FileStorage, RingVerifier};
use remote_settings_client::{Client, Record};
use serde::Deserialize;
use serde_json::json;
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_url = option_env!("SERVER_URL").unwrap_or("http://localhost:8888/v1");
    let authorization = option_env!("AUTHORIZATION").unwrap_or("");
    // The `product-integrity` collection is automatically created in CI because
    // we use the `testing.ini` config which will create all signed resources on startup.
    // See `KINTO_SIGNER_RESOURCES` in `.circleci/config.yml`.
    let collection = option_env!("COLLECTION").unwrap_or("product-integrity");

    env_logger::init();
    set_backend(&ReqwestBackend).unwrap();

    println!("Connect to local server {}", server_url);
    let editor_client = Client::builder()
        .http_client(Box::new(ViaductClient))
        .server_url(server_url)
        .authorization(authorization)
        .collection_name(collection)
        .build()
        .unwrap();

    println!("main-workspace/{}: Create a record", collection);
    editor_client
        .store_record(Record::new(json!({
          "id": "my-key",
          "foo": "bar"
        })))
        .await?;

    println!("main-workspace/{}: Request review from peers", collection);
    editor_client.request_review("I made changes").await?;

    print!(
        "main-workspace/{}: Fetching preview records with default `Verifier`...",
        collection
    );
    let mut preview_client = Client::builder()
        .http_client(Box::new(ViaductClient))
        .server_url(server_url)
        .bucket_name("main-preview")
        .collection_name(collection)
        .build()
        .unwrap();

    let records = preview_client.get().await?;
    println!("{} record(s) published", records.len());

    println!("\n\n");

    println!("Fetch all Remote Settings collections from PROD server.");
    let url = "https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset?_expected=0";
    let response =
        tokio::task::spawn_blocking(move || Request::get(Url::parse(url).unwrap()).send().unwrap())
            .await
            .unwrap();
    let collections: KintoPluralResponse<LatestChangeEntry> = response.json().unwrap();

    for collection in &collections.changes {
        let cid = format!("{}/{}", collection.bucket, collection.collection);
        print!("{}: ", cid);

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
        println!("Found {} records", records.len());
    }

    Ok(())
}
