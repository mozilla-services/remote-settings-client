# Change Log

## 1.1.0 (2022-02-18)

**New features**
- Add support for write methods (#172)

**Internal Changes**
- Bump rc_crypto from v87.1.0 to v93.2.0 (#171, #185, #197)

## 1.0.1 (2021-12-14)

**Bug fixes**
- Make the demo return failure error codes (#167)
- Fix canonical JSON serialization of records (#168)

**Internal Changes**
- Bump rc_crypto from v87.0.0 to v87.1.0 (#164)


## 1.0.0 (2021-12-01)

**Breaking Changes**
- Re-introduce the async/await API (#158)

**New features**
- Add attachment support (#160)
- Add an abstraction around the HTTP client (#153)
- Signature verification using `rc_crypto` (#133)
- Verify certificate chain (#94)
- Handle Backoff header (#92)
- Add `Sync` to the `Storage` trait (#161)

**Internal Changes**
- Run clippy in CI (#155, #157)
- Upgraded `viaduct` and `rc_crypto` to v87.0.0 (#150)
- x509-parser requirement from 0.10.0 to 0.12.0 (#141)
- Update httpmock requirement from 0.5.6 to 0.6.2 (#137)
- Update x509-parser requirement from 0.9.2 to 0.10.0 (#135)
- Update env_logger requirement from 0.8.3 to 0.9.0 (#134)
