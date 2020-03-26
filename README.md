<p align="center">
  <img width="120" src="https://github.com/etesync/etesync-web/blob/master/src/images/logo.svg" />
  <h1 align="center">EteSync - Secure Data Sync</h1>
</p>

A C and Rust client library for EteSync

This package is implemented in Rust and exposes a C API for people to use. The C API is still in alpha stage and
subject to stage, and the Rut API should be considered internal and experimental for now.

![GitHub tag](https://img.shields.io/github/tag/etesync/etesync-rs.svg)
[![Chat on freenode](https://img.shields.io/badge/irc.freenode.net-%23EteSync-blue.svg)](https://webchat.freenode.net/?channels=#etesync)


# Build

To build:
```
$ cargo build
```

To run the tests you first need an [EteSync server running](https://github.com/etesync/server) locally, because the tests test against a real server.
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

There is also a basic example EteSync client that resides in `example.c`. There are compilation instructions at the top of it, so just follow them for more information.
