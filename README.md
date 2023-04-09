<p align="center">
  <img width="120" src="https://github.com/etesync/etesync-web/blob/master/src/images/logo.svg" />
  <h1 align="center">Etebase - Encrypt Everything</h1>
</p>

A Rust library for Etebase

In addition to exposing a Rust API, this library forms the basis of other Etebase libraries, for example libetebase.

![GitHub tag](https://img.shields.io/github/tag/etesync/etesync-rs.svg)
[![Build Status](https://github.com/etesync/etebase-rs/actions/workflows/build.yml/badge.svg)](https://github.com/etesync/etebase-rs/actions)
[![Crates.io](https://img.shields.io/crates/v/etebase)](https://crates.io/crates/etebase)
[![docs.rs](https://docs.rs/etebase/badge.svg)](https://docs.rs/etebase/)
[![Chat with us](https://img.shields.io/badge/chat-IRC%20|%20Matrix%20|%20Web-blue.svg)](https://www.etebase.com/community-chat/)

# Documentation

In addition to the API documentation, there are docs available at https://docs.etebase.com

# Minimum supported Rust version (MSRV)

The current MSRV is 1.63.0. Changes to the MSRV are not considered breaking and may occur in any patch release, it is however guaranteed that
at least the previous Rust version will always be supported. This results in a three-month grace period from when a new Rust verion is released
until it may become required.

# Build

To build:
```
$ cargo build
```

To test, run the `etesync/test-server` image using the latest version, e.g.,

```
docker run -p 3735:3735 -d etesync/test-server:latest
```

and then set `ETEBASE_TEST_HOST` to the host:port on which that is running; for the docker invocation above, that's
```
export ETEBASE_TEST_HOST=localhost:3735
```

and then run the tests:

```
$ cargo test -- --test-threads 1
```

Please note that the tests run against the local server so we need to run them single threaded to make sure they don't clash.
