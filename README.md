# Remote-Settings-Client

A Remote-Settings Client built using Rust to read collection data.

- Read-Only
- Customizable Signature Verification
<!-- - Cross-Platform
- Robust -->
- Rust!

## Example

Below example uses [Tokio](https://tokio.rs) and utilizes some optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
tokio = { version = "0.2.21", features = ["macros", "tcp"] }
log = "0.4.0"
env_logger = "0.7.1"
```

### Fetching Records from Collection
```rust,no_run
use remote_settings::{Client};

#[tokio::main]
async fn main() {
  ...  
  // we pass None for Verifier parameter to fall back to default verifier implementation
  // here server_url and bucket_name will be set to default values
  let client = Client::create_with_collection("example-collection", None);
  
  match client.get(expected).await {
        Ok(records) => println!("{:?}", records),
        Err(error) => println!("Could not fetch records: {:?}", error)
  };
  ...
}
```

### Logging

Dependencies: [log](https://docs.rs/log), [env_logger](https://docs.rs/env_logger)

```toml
[dependencies]
log = "0.4.0"
env_logger = "0.7.1"
```

For logging, run `RUSTLOG={debug/info} cargo run` to see debug/info log messages from the Remote-Settings-Client (error messages are printed by default)

```rust,no_run
#[tokio::main]
async fn main() {
  env_logger::init() // initialize logger
}
```

For more examples, go to the [demo project](rs-client-demo)

## License

Licensed under Mozilla Public License, Version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/)
