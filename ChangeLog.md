# Changelog

## Unreleased
### Features

### Changes

## Version 0.6.1
### Features

### Fixes
* openssl: bump to address CVE-2025-3416

### Changes


## Version 0.6.0
### Features
* Added `utils::randombytes_array()` function to create fixed-sized arrays of random numbers

### Fixes
* Loosened the argument types for `ItemMetadata::set_*()` methods to allow passing `String`s directly
* Loosened the argument types for several methods to take any `IntoIterator`, not just `Iterator`
* Various documentation fixes
* Bump version of `remove_dir_all` to fix a CVE

### Changes
* Renamed `SignedInvitation::from_*()` methods to `sender_*()` to avoid confusing them with constructors.
* Renamed the `Account::is_etebase_server()` function to a method - `Client::is_server_valid()`.
* `Error` now implements `Eq`.
* Made some error messages more specific
* Most of the `test_helpers` module has been removed. This module was hidden from documentation and never
  meant for public use.
* The `user` field of `Account` has been made private. Its type (`LoginResponseUser`) was never publicly
  accessible, so no application should have had a use for it.

## Version 0.5.3
* Upgrade dependencies - ignore package lock. Upgrade to absolute latest.

## Version 0.5.2
* Upgrade dependencies

## Version 0.5.1
* Update sodiumoxide dependency (it broke API)
* Check for exact key length

## Version 0.5.0
* Implement fetch_multi for fetching multiple items by uid
* Implement prefetch, pre-upload and partial items

## Version 0.4.1
* Document all of the public APIs

## Version 0.4.0
* Relicense to BSD-3-Clause
* Improve documentation

## Version 0.3.0
* Initial version uploaded to crates.io
