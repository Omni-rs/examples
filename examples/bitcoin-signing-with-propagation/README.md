# Bitcoin Signing with Propagation

This example demonstrates how to sign a Bitcoin transaction using the MPC  (Multi-Party Computation) signer from a contract and propagate the transaction to the Bitcoin network (RegTest mode).

## Overview

1. **Setup Bitcoin Network**: We use `bitcoind` to simulate a Bitcoin network.
2. **Create Users**: We create two users (Bob and Alice) with their respective private keys.
3. **Generate Blocks**: We generate blocks to the users' addresses to simulate real transactions.

