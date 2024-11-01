# Bitcoin Signing Multiple UTXOs (Segwit)

This example demonstrates how to sign a Bitcoin transaction (segwit) with multiple UTXOs using the MPC  (Multi-Party Computation) signer from a NEAR contract and verify the signatures.

## Overview

1. **Setup Bitcoin Network**: We use `bitcoind` to simulate a Bitcoin network.
2. **Create Users**: We create 1 user (Bob) with their respective private key.
3. **Derive Bitcoin address**: We derive the Bitcoin address from the NEAR contract account.
4. **Generate UTXOs**: We "give" UTXOs to the derived Bitcoin address that is controlled by the NEAR contract by generating blocks to the derived address. 
5. **Transfer BTC**: We transfer BTC from the derived Bitcoin address to Bob, but since the derived Bitcoin address is controlled by the MPC Signer and the NEAR contract account, we need to sign the transaction using the MPC signer that will allow us to transfer BTC to Bob.

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
just run bitcoin-signing-segwit-multiple-utxos --deploy
```

If you want to run the test without deploying the contract, run the following command:

```bash
just run bitcoin-signing-segwit-multiple-utxos
```
