# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-07-28

### Added
- Complete `AmberSigner` class implementation extending the base `Signer` class
- **Authentication & Session Management:**
  - `signIn()` method with support for retrieving public keys from Amber app
  - `attemptAutoSignIn()` for automatic session restoration using persisted public keys
  - `signOut()` method with complete session cleanup
  - Persistent storage of public keys using CustomData for session persistence
- **Event Signing:**
  - `sign<E>()` method for signing partial models into fully signed Nostr events
  - Support for signing multiple events in a single call
  - Special handling for PartialDirectMessage with automatic NIP-04 encryption
- **Encryption/Decryption Support:**
  - `nip04Encrypt()` and `nip04Decrypt()` methods for NIP-04 message encryption
  - `nip44Encrypt()` and `nip44Decrypt()` methods for NIP-44 message encryption (currently using NIP-04 implementation)
- **Device Integration:**
  - `isAvailable` getter to check if Amber app is installed and available
  - Automatic Amber app detection and configuration
- **Error Handling:**
  - Comprehensive error handling with meaningful exception messages
  - Graceful handling of missing Amber app installation
  - Robust auto sign-in with fallback mechanisms

### Changed
- Updated package version to 0.2.0
- Updated dependency constraints:
  - `models: ^0.3.3`
  - `flutter_lints: ^5.0.0`
- Added dependency overrides for models package from git repository

### Technical Details
- Uses `signer_plugin` for communication with Amber app
- Implements internal custom data signer for persistent storage operations
- Supports both manual and automatic session management
- Comprehensive documentation with usage examples for all public methods
- Null-safe implementation with proper error handling

### Dependencies
- Added `signer_plugin` from git repository (ref: baa5b2)
- Models dependency updated to version ^0.3.0 with git override
- Minimum Dart SDK: 3.8.0
- Minimum Flutter version: 1.17.0 