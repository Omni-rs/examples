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

- [x] [Simple encoding](./examples/evm-simple-encoding)
- [x] [Simple encoding passing args](./examples/evm-simple-encoding-passing-args)
- [x] [Simple encoding with signature](./examples/evm-simple-encoding-with-signature)
- [ ] [Simple signing](#)
- [ ] [Signing with propagation](#)

### NEAR

- [x] [Simple encoding](./examples/near-simple-encoding)
- [x] [Simple encoding passing args](./examples/near-simple-encoding-passing-args)
- [ ] [Simple encoding with signature](#)
- [ ] [Simple signing](#)
- [ ] [Signing with propagation](#)

### Bitcoin

- [x] [Simple encoding](./examples/bitcoin-simple-encoding)
- [ ] [Simple encoding passing args](./examples/bitcoin-simple-encoding-passing-args)
- [ ] [Simple signing (legacy)](#)
- [x] [Simple signing (segwit)](./examples/bitcoin-signing-segwit/)
- [x] [Signing with propagation (legacy)](./examples/bitcoin-signing-with-propagation-legacy)
- [ ] [Signing with propagation (segwit)](#)
- [x] [Signing (segwit) multiple UTXOs](./examples/bitcoin-signing-segwit-multiple-utxos/)
- [ ] [Signing (segwit) multiple UTXOs with propagation](#)
- [ ] [Runes Etching](#)
- [ ] [Ordinals inscriptions](#)
