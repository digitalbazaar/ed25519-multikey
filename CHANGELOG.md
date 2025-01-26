# @digitalbazaar/ed25519-multikey ChangeLog

## 1.3.1 - 2025-01-26

### Fixed
- Fix canonicalized raw secret key export length.

## 1.3.0 - 2024-10-02

### Added
- Include `id` and `controller` properties when importing key types of
  `JsonWebKey` or `JsonWebKey2020`.

## 1.2.0 - 2024-08-20

### Added
- Allow 32-byte or 64-byte secret key values. The actual secret part of
  the secret key is the first 32 bytes, but some implementations concatenate
  the public key (an additional 32 bytes) onto the "secret key bytes"; this
  feature allows either to be used.

## 1.1.0 - 2024-03-17

### Added
- Enable loading keys from `publicKeyJwk` via `from()` and converting
  to/from JWK.

### Fixed
- Allow `@context` array values in multikeys.

## 1.0.2 - 2024-01-25

### Fixed
- Do not export undefined fields for `secretKeyMultibase` and `revoked`
  when they are not present.

## 1.0.1 - 2023-04-14

### Fixed
- Update `.from()` method to not modify key input.

## 1.0.0 - 2022-09-08

### Added
- Initial version.
