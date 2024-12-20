# EVM: Simple Signing with Propagation

This example demonstrates how to sign an EVM transaction using the MPC  (Multi-Party Computation) signer from a NEAR contract and propagate the transaction to the EVM Chain (local network).

## Overview

1. **Setup EVM Network**: We use `Anvil` to simulate an EVM network.
2. **Create Users**: We create 1 user (Bob) with their respective private key.
3. **Derive EVM address**: We derive the Bitcoin address from the NEAR contract account.
4. **Send Fund**: We "give" UTXOs to the derived Bitcoin address that is controlled by the NEAR contract by generating blocks to the derived address. 
5. **Transfer ETH**: We transfer BTC from the derived Bitcoin address to Bob, but since the derived Bitcoin address is controlled by the MPC Signer and the NEAR contract account, we need to sign the transaction using the MPC signer that will allow us to transfer BTC to Bob.
6. **Transaction Propagation**: Using the transaction payload signed, we submit this to the Anvil node.

## How to run the example

Since this example deploys the NEAR contract to the NEAR testnet, you need to have the NEAR CLI and a `config.json` file with the following structure:

```json
{
    "account_id": "<your_account_id>.testnet",
    "public_key": "<your_public_key>",
    "private_key": "<your_private_key>"
}
```

Then run the following command to deploy the contract:

```bash
just run evm-signing-with-propagation --deploy
```

If you want to run the test without deploying the contract, run the following command:

```bash
just run evm-signing-with-propagation
```
