use remote_settings_client::client::Client as rs_client;
// I would remove one level here and remove the `as rs_client`.
// use remote_settings::Client

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let client = rs_client::create_with_collection("url-classifier-skip-urls").await;

    println!("{:?}", client);

    println!("Fetching records using RS client");

    client.get(0).await;
    // What error can it return here?
}
