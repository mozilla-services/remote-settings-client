use {
    super::{Collection, SignatureError, Verification},
    log::debug,
};

pub struct DummyVerifier {}

impl Verification for DummyVerifier {
    fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
        debug!("default verifier implementation");
        Ok(())
    }
}
