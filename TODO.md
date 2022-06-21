# TODO

This file tracks planned changes to the project, especially breaking changes that have to wait
until the next major release.

## Planned changes for next major release

- Change argument types in `src/service.rs` for public and private keys to use `[u8; 32]` instead
  of `[u8]`. This should remove all the `ProgrammingError`s resulting from failed `try_into()` calls.
