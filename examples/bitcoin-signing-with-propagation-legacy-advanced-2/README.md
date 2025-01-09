# Bitcoin Signing with Propagation (Legacy) Advanced

This example demonstrates how to sign a Bitcoin transaction (legacy) using the MPC  (Multi-Party Computation) signer from a NEAR contract and propagate the transaction to the Bitcoin network (RegTest mode).

The example makes use of a callback pattern and makes the sighash and raw transaction creation in one single transaction.

## How to run the example

Since this example deploys the NEAR contract to the NEAR testnet, you need to have the NEAR CLI and a `deployer.json` file with the following structure:

```json
{
    "account_id": "<your_account_id>.testnet",
    "public_key": "<your_public_key>",
    "private_key": "<your_private_key>"
}
```

Then, to run the test, simply run the following command:

```bash
just run bitcoin-signing-with-propagation-legacy-advanced
```
