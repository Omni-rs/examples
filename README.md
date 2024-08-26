# Omni Transaction Rust library examples

This repository contains a set of examples that demonstrate how to use the main features of OmniTransactionBuilder.

[![Telegram chat][telegram-badge]][telegram-url]

[telegram-badge]: https://img.shields.io/endpoint?color=neon&style=for-the-badge&url=https://tg.sumanjay.workers.dev/chain_abstraction
[telegram-url]: https://t.me/chain_abstraction

## Pre requisites

- [Rust](https://www.rust-lang.org/)

- [Near CLI](https://github.com/near/near-cli)

- [Cargo Near](https://github.com/near/cargo-near)

- [Just](https://github.com/casey/just)

## Usage

To run an example, use the command `just run <example name>`.

For example:

```bash
$ just run evm-simple-encoding
```

## Examples architecture

Each example contains a Near smart contract with unit tests and an integration test located in the `tests` folder.

The structure of each example is as follows:

- src
  - lib.rs # the Near contract
- tests
  - test_contract.rs # the integration test

The recommendation is to go thought each example and read the annotated integration test.

## Examples list

### EVM

- [x] [Simple encoding](./evm-simple-encoding)
- [x] [Simple encoding passing args](./evm-simple-encoding-passing-args)
- [x] [Simple encoding with signature](./evm-simple-encoding-with-signature)
- [x] [Simple signing](./evm-simple-signing)
- [x] [Simple signing and propagating](./evm-simple-signing-and-propagating)

### NEAR

- [x] [Simple encoding](./near-0-simple-encoding)
- [ ] [Multiple encoding](./near-1-multiple-encoding)
- [ ] [Simple signing](./near-2-simple-signing)
- [ ] [Multiple signing](./near-3-multiple-signing)
- [ ] [Advance signing](./near-4-advance-signing)

