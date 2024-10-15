# Bitcoin Signing with Propagation

This example demonstrates how to sign a Bitcoin transaction using the MPC  (Multi-Party Computation) signer from a contract and propagate the transaction to the Bitcoin network (RegTest mode).

## Overview

1. **Setup Bitcoin Network**: We use `bitcoind` to simulate a Bitcoin network.
2. **Create Users**: We create two users (Bob and Alice) with their respective private keys.
3. **Generate Blocks**: We generate blocks to the users' addresses to simulate real transactions.

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
just run bitcoin-signing-with-propagation
```

