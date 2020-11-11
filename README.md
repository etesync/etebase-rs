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
[![Chat on freenode](https://img.shields.io/badge/irc.freenode.net-%23EteSync-blue.svg)](https://webchat.freenode.net/?channels=#etesync)


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

# Testing the C API

There are tests for the C API which can be run like this:
```
$ cd c_tests
$ make check
```

There is also a basic example Etebase client that resides in `example.c`. There are compilation instructions at the top of it, so just follow them for more information.
