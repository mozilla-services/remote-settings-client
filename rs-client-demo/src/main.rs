/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use env_logger;
use remote_settings_client::{Client, Collection, SignatureError, Verification};
use viaduct::{set_backend, Request};
pub use url::{ParseError, Url};
pub use viaduct_reqwest::ReqwestBackend;
use serde_json;
use serde::Deserialize;

struct CustomVerifier {}
#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    data: Vec<T>,
}

#[derive(Deserialize, Debug)]
pub struct LatestChangeResponse {
    pub id: String,
    pub last_modified: u64,
    pub bucket: String,
    pub collection: String,
    pub host: String,
}

impl Verification for CustomVerifier {
    fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
        Ok(()) // everything is verified!
    }
}

fn print_records(records: &[serde_json::Value]) {
    for record in records {
        println!("{:?}", record);
    }
}

fn main() {
    env_logger::init();
    set_backend(&ReqwestBackend).unwrap();

    println!("Fetching records using RS client with default Verifier");

    let client = Client::create_with_collection("url-classifier-skip-urls", None);

    match client.get() {
        Ok(records) => {
            print_records(&records)
        },
        Err(error) => println!("Error fetching/verifying records: {:?}", error),
    };

    let url = "https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records";
    let response = Request::get(Url::parse(&url).unwrap()).send().unwrap();
    let collections: KintoPluralResponse<LatestChangeResponse> = response.json().unwrap(); 

    let mut failed_fetch = Vec::new();

    for collection in &collections.data {
        
        let client = Client::create_with_bucket_collection(&collection.bucket, &collection.collection, None);

        println!("Fetching records");

       match client.get() {
           Ok(records) => print_records(&records),
           Err(error) => {
               println!("Error fetching/verifying records: {:?}", error);
               failed_fetch.push(collection);
           },
       };

        println!(" -- --- -- -- -- -- - -");
    }

    println!("The failed collections are {:?}", failed_fetch);

    println!("Fetching records using RS client with custom Verifier");
    let client_with_custom_verifier = Client::create_with_collection(
        "url-classifier-skip-urls",
        Some(Box::new(CustomVerifier {})),
    );

    match client_with_custom_verifier.get() {
        Ok(records) => print_records(&records),
        Err(error) => println!("Error fetching/verifying records: {:?}", error),
    };
}
