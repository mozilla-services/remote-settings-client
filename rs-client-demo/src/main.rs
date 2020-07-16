/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use env_logger;
use remote_settings_client::{Client, Collection, SignatureError, Verification};
pub use viaduct::{set_backend};
pub use viaduct_reqwest::ReqwestBackend;
use serde_json;

struct CustomVerifier {}

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

    match client.get(expected) {
        Ok(records) => {
            print_records(&records)
        },
        Err(error) => println!("Could not fetch records: {:?}", error),
    };

    // let collections = vec![
    //         ("main", "normandy-recipes"),
    //         ("main", "normandy-recipes-capabilities"),
    //         ("main", "messaging-experiments"),
    //         ("main-preview", "messaging-experiments"),
    //         ("main", "cfr"),
    //         ("main-preview", "cfr"),
    //         ("main-preview", "public-suffix-list"),
    //         ("blocklists", "addons-bloomfilters"),
    //         ("blocklists", "addons"),
    //         ("main", "ms-language-packs"),
    //         ("main","search-config"),
    //         ("main","search-default-override-allowlist"),
    //         ("main-preview","ms-language-packs"),
    //         ("blocklists-preview","addons"),
    //         ("main-preview","fxmonitor-breaches"),
    //         ("main","pioneer-study-addons"),
    //         ("main-preview","pioneer-study-addons"),
    //         ("security-state","cert-revocations"),
    //         ("security-state-preview","cert-revocations"),
    //         ("main","url-classifier-skip-urls"),
    //         ("main-preview","url-classifier-skip-urls"),
    //         ("main","message-groups"),
    //         ("main-preview","message-groups"),
    //         ("blocklists","plugins"),
    //         ("blocklists-preview","plugins"),
    //         ("main-preview","search-config"),
    //         ("main","mobile-experiments"),
    //         ("main-preview","mobile-experiments"),
    //         ("main","whats-new-panel"),
    //         ("main-preview","whats-new-panel"),
    //         ("main","windows-default-browser-agent"),
    //         ("main-preview","windows-default-browser-agent"),
    //         ("main","partitioning-exempt-urls"),
    //         ("main-preview","partitioning-exempt-urls"),
    //         ("security-state-preview","intermediates"),
    //         ("security-state","intermediates"),
    //         ("blocklists","certificates"),
    //         ("security-state","onecrl"),
    //         ("security-state-preview", "onecrl"),
    //         ("main-preview","regions"),
    //         ("main","regions"),
    //         ("main","fxmonitor-breaches"),
    //         ("main-preview","search-default-override-allowlist"),
    //         ("main","cfr-fxa"),
    //         ("main-preview","cfr-fxa"),
    //         ("main", "personality-provider-recipe"),
    //         ("main-preview", "personality-provider-recipe"),
    //         ("main", "personality-provider-models"),
    //         ("main-preview", "personality-provider-models"),
    //         ("main", "cfr-ml-control"),
    //         ("main-preview", "cfr-ml-control"),
    //         ("main", "cfr-ml-experiments"),
    //         ("main-preview", "cfr-ml-experiments"),
    //         ("main", "cfr-ml-models"),
    //         ("main", "public-suffix-list"),
    //         ("blocklists-preview", "qa"),
    //         ("main", "hijack-blocklists"),
    //         ("main-preview", "hijack-blocklists"),
    //         ("main", "cfr-srg"),
    //         ("main-preview", "cfr-srg"),
    //         ("main", "language-dictionaries"),
    //         ("main-preview", "language-dictionaries"),
    //         ("main", "fftv-experiments"),
    //         ("main-preview", "fftv-experiments"),
    //         ("main", "tracking-protection-lists"),
    //         ("main-preview", "tracking-protection-lists"),
    //         ("main", "anti-tracking-url-decoration"),
    //         ("main-preview", "anti-tracking-url-decoration"),
    //         ("main", "tippytop"),
    //         ("main-preview", "tippytop"),
    //         ("main", "focus-experiments"),
    //         ("main-preview", "focus-experiments"),
    //         ("main", "fenix-experiments"),
    //         ("main-preview", "fenix-experiments"),
    //         ("main", "lite-experiments"),
    //         ("main-preview", "lite-experiments"),
    //         ("main", "sites-classification"),
    //         ("main-preview", "sites-classification"),
    //         ("main", "rocket-prefs"),
    //         ("main-preview", "rocket-prefs"),
    //         ("blocklists-preview", "gfx"),
    //         ("blocklists", "qa"),
    //         ("pinning-preview", "pins"),
    //         ("pinning", "pins"),
    //         ("blocklists", "gfx")
    //     ];

    // let mut failed_fetch = Vec::new();

    // for collection in &collections {
    //     println!(" -- --- -- -- -- -- - -");
    //     println!("{}, {}", collection.0, collection.1);
        
    //     let client = Client::create_with_bucket_collection(collection.0, collection.1, None);

    //     println!("Fetching records");

    //    match client.get(0) {
    //        Ok(records) => println!("Successful fetch"),
    //        Err(error) => {
    //            println!("Could not fetch records: {:?}", error);
    //            failed_fetch.push(collection);
    //        },
    //    };

    //     println!(" -- --- -- -- -- -- - -");
    // }

    //println!("The failed collections are {:?}", failed_fetch);

    println!("Fetching records using RS client with custom Verifier");
    let client_with_custom_verifier = Client::create_with_collection(
        "url-classifier-skip-urls",
        Some(Box::new(CustomVerifier {})),
    );

    match client_with_custom_verifier.get(expected) {
        Ok(records) => print_records(&records),
        Err(error) => println!("Could not fetch records: {:?}", error),
    };
}
