# EVM: Local Signing with Propagation

This example demonstrates how to sign an EVM transaction using a local signer from a NEAR contract and propagate the transaction to the EVM Chain (local network from the OmniBox).

## Overview

1. **Setup EVM Network**: We use `Anvil` to simulate an EVM network.
2. **Create Users**: OmniBox creates 2 users (Alice and Bob) by default, so we simply use Alice as the destination EVM address.
3. **Hash transaction in the NEAR contract**: The smart contract is responsible of encoding the transaction. Returning the hash to be signed.
4. **Transfer ETH**: We transfer `0.01 ETH` from Bob to Alice.
5. **Transaction Propagation**: Using the transaction payload signed, we submit this to the Anvil node.

## How to run the example

Since this example deploys the NEAR contract to the NEAR testnet, you need to have the NEAR CLI and a `deployer.json` file with the following structure:

```json
{
    "account_id": "<your_account_id>.testnet",
    "public_key": "<your_public_key>",
    "private_key": "<your_private_key>"
}
```

Then run the following command to test the contract:

```bash
just run evm-local-signing-with-propagation
```
