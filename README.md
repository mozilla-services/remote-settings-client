# Remote Settings Client

> **Warning**: This repository was archived in January 2025. The official Rust client for Remote Settings now lives at https://github.com/mozilla/application-services/tree/main/components/remote_settings

A Rust Remote Settings Client to fetch collection data.

Available features:

- Synchronization of local storage via [`rkv`](https://github.com/mozilla/rkv/), memory, or filesystem
- Signatures and cert chains verification via NSS [`rc_crypto`](https://github.com/mozilla/application-services/tree/main/components/support/rc_crypto) or [`ring`](https://lib.rs/crates/ring)+[`oid-registry`](https://lib.rs/crates/oid-registry)
- Download of attachments
- Write operations on records
- Signoff operations (request review, approve, reject)

<!-- - Cross-Platform
- Robust -->

Relies on Mozilla's [viaduct](https://github.com/mozilla/application-services/tree/v75.0.0/components/viaduct) for its pluggable HTTP backend (eg. `reqwest` or `FFI` on Android).

See also the `Storage` and `Verification` traits to extend or customize the client behaviour.

## Quick start

`Cargo.toml`:

```toml
[dependencies]
remote-settings-client = { version = "0.1", features = ["ring_verifier"] }
viaduct = { git = "https://github.com/mozilla/application-services", rev = "v75.2.0"}
viaduct-reqwest = { git = "https://github.com/mozilla/application-services", rev = "v75.2.0"}
```

Minimal example:

```rust
use remote_settings_client::Client;
pub use viaduct::set_backend;
pub use viaduct_reqwest::ReqwestBackend;

fn main() {
  set_backend(&ReqwestBackend).unwrap();

  let client = Client::builder()
    .collection_name("search-config")
    .build();

  match client.get() {
    Ok(records) => println!("{:?}", records),
    Err(error) => println!("Error fetching/verifying records: {:?}", error),
  };
}
```

See also our [demo project](rs-client-demo)!

## Documentation

[Crate documentation](https://docs.rs/remote_settings_client)

## Logging

Using [env_logger](https://docs.rs/env_logger), the log level can be set via an environ variable:

`RUSTLOG={debug/info} cargo run`

```rust
fn main() {
  env_logger::init() // initialize logger
  ..
}
```

## License

Licensed under Mozilla Public License, Version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/)
