# EVM: Remote Signing with Propagation

This example demonstrates how to sign an EVM transaction using the MPC (Multi-Party Computation) signer from a NEAR contract and propagate the transaction to the EVM Chain (local network).

## Overview

1. **Setup EVM Network**: We use `Anvil` to simulate an EVM network.
2. **Create Users**: OmniBox creates 2 users (Alice and Bob) by default, so we simply use Alice as the destination EVM address.
3. **Derive EVM address**: We derive the EVM address of the NEAR contract account (derived EVM account).
4. **Set initial balance**: We set the balance of the derived EVM account to 100 ETH (This address is controlled by the NEAR contract).
5. **Transfer ETH**: We transfer `0.01 ETH` from the derived EVM account to Alice, but since the derived account is controlled by the MPC Signer and the NEAR contract account, we need to sign the transaction using the MPC signer that will allow us to transfer Eth to Alice.
6. **Transaction Propagation**: Using the transaction payload signed, we submit this to the Anvil node.

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
just run evm-remote-signing-with-propagation
```
