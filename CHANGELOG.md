# @digitalbazaar/ed25519-multikey ChangeLog

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
