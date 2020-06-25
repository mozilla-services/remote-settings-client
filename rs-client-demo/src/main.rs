use remote_settings_client::{Collection, Client, Verification, SignatureError};
use async_trait::async_trait;

struct CustomVerifier {}

#[async_trait]
impl Verification for CustomVerifier {
    async fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        Ok(()) // everything is verified!
    }
}

#[tokio::main]
async fn main() {
    println!("Fetching records using RS client with default Verifier");

    let client = Client::create_with_collection("url-classifier-skip-urls", None);

    let expected = 0; // used to specify file version for cache busting
    
    match client.get(expected).await {
        Ok(collection) => println!("{:?}", collection),
        Err(error) => println!("Could not fetch records: {}", error)
    };

    println!("Fetching records using RS client with custom Verifier");
    let client_with_custom_verifier = Client::create_with_collection("url-classifier-skip-urls", Some(Box::new(CustomVerifier{})));
    
    match client_with_custom_verifier.get(expected).await {
        Ok(collection) => println!("{:?}", collection),
        Err(_) => println!("Could not fetch records: {}", error)
    };
}
