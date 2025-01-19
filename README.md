# Omni Transaction Rust library examples

This repository contains a set of examples that demonstrate how to use the main features of the [Omni Transaction library] and [OmniBox].

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

- [X] [Encoding](./examples/evm-simple-encoding)
- [X] [Encoding passing args](./examples/evm-simple-encoding-passing-args)
- [X] [Encoding with signature](./examples/evm-simple-encoding-with-signature)
- [X] [Local signing with propagation](./examples/evm-local-signing-with-propagation/)
- [X] [Remote (MPC) signing with propagation](./examples/evm-remote-signing-with-propagation/)

### NEAR

- [X] [Simple encoding](./examples/near-simple-encoding)
- [X] [Simple encoding passing args](./examples/near-simple-encoding-passing-args)

### Bitcoin

- [X] [Encoding (P2PKH and P2WPKH)](./examples/bitcoin-simple-encoding)
- [X] [Signing (segwit)](./examples/bitcoin-signing-segwit/)
- [X] [Signing (segwit) multiple UTXOs](./examples/bitcoin-signing-segwit-multiple-utxos/)
- [X] [Signing with propagation (segwit)](./examples/bitcoin-signing-with-propagation-segwit/)
- [X] [Signing with propagation (legacy)](./examples/bitcoin-signing-with-propagation-legacy)
- [X] [Signing with propagation advanced (legacy)](./examples/bitcoin-signing-with-propagation-legacy)
- [X] [Signing with propagation using a Rust client (legacy)](./examples/bitcoin-signing-with-propagation-legacy)
- [X] [Signing with testnet propagation and local signing](./examples/bitcoin-local-signing-with-propagation-legacy-advanced/)
- [X] [Signing with testnet propagation and remote signing (MPC)](./examples/bitcoin-remote-signing-with-propagation-legacy-advanced/)
- [ ] [Runes Etching](#)
- [ ] [Ordinals inscriptions](#)

<!-- References -->
[Omni Transaction library]: https://github.com/near/omni-transaction-rs
[OmniBox]: https://github.com/Omni-rs/omni-box