# Morphing Techniques

Morphing contracts change their behavior depending on the context.

## Red-Pill

The red-pill technique detects simulation environment to disable its exploits upon scrutiny. 

### Evades

Live tests in transaction simulations: often performed by wallets before sending a transaction.

### How

The contract detects simulation environments by:

- comparing the global variables with settings found in simulated environments:
  - `block.basefee` with
  - `block.coinbase` with `0x0000000000000000000000000000000000000000`
  - `tx.gasprice` with

Then it triggers legitimate code in simulation contexts and malicious code on the mainnet.

### Samples

The contract [FakeWethGiveaway](red-pill/FakeWethGiveaway.sol) checks the current block miner’s address:

```solidity
function checkCoinbase() private view returns (bool result) {
    assembly {
        result := eq(coinbase(), 0x0000000000000000000000000000000000000000)
    }
}
```

When null (test env), it actually sends a reward and otherwise it just accepts transfers without doing anything.s

### Detection & Countermeasures

1. Looking for unusual opcodes: typically `block.coinbase`.

2. Replaying transactions and fuzzing the global variables.

### Resources

- [Zengo article][red-pill-polygon-fake-weth-giveaway]

## Evil Upgrades

[red-pill-polygon-fake-weth-giveaway]: https://polygonscan.com/address/0x15391A813d255e76de9b6b6d60df75c73f91121a#code
[red-pill-zengo-article]: https://zengo.com/zengo-uncovers-security-vulnerabilities-in-popular-web3-transaction-simulation-solutions-the-red-pill-attack/
