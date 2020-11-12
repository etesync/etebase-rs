<p align="center">
  <img width="120" src="https://github.com/etesync/etesync-web/blob/master/src/images/logo.svg" />
  <h1 align="center">Etebase - Encrypt Everything</h1>
</p>

A Rust library for Etebase

In addition to exposing a Rust API, this library forms the basis of other Etebase libraries, for example libetebase.

![GitHub tag](https://img.shields.io/github/tag/etesync/etesync-rs.svg)
[![Build Status](https://travis-ci.com/etesync/etebase-rs.svg?branch=master)](https://travis-ci.com/etesync/etebase-rs)
[![Crates.io](https://img.shields.io/crates/v/etebase)](https://crates.io/crates/etebase)
[![docs.rs](https://docs.rs/etebase/badge.svg)](https://docs.rs/etebase/)
[![Chat with us](https://img.shields.io/badge/chat-IRC%20|%20Matrix%20|%20Web-blue.svg)](https://www.etebase.com/community-chat/)


# Build

To build:
```
$ cargo build
```

To run the tests you first need an [Etebase server running](https://github.com/etesync/server) locally, because the tests test against a real server.
You will also need to create a special user called `test@localhost` with password `SomePassword`, which the test suite expects.
```
$ cargo test -- --test-threads 1
```

Please note that the tests run against the local server so we need to run them single threaded to make sure they don't clash.
