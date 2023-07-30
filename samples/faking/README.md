# Faking Techniques

Disguise malicious code as well-known or vulnerable code (honeypots) to bait users.

## Inheritance Overriding

### Evades

Source code reviews with subtle exploitation of the compilation process.

### How

The malicious contract inherits from standard code like `Ownable`, `Upgradeable`, etc.

It overwrites key elements by:

- adding a variable definition for an existing keyword
- polymorphism, which allows to have several versions of a function

Then single keyword can refer to different implementations depending on its context.

The resulting contract doesn't behave like its parent, while looking legitimate.

### Samples

#### Attribute Overwriting

`KingOfTheHill` inherits from `Ownable` but the original `owner` cannot be changed:

```solidity
contract KingOfTheHill is Ownable {
    address public owner; // different from the owner in Ownable

    function () public payable {
        if(msg.value > jackpot) owner = msg.sender; // local owner
        jackpot += msg.value;
    }
    function takeAll () public onlyOwner { // owner from Ownable = contract creator
        msg.sender.transfer(this.balance);
        jackpot = 0;
    }
}
```

In the modifier on `takeAll`, the `owner` points to the contract creator.
It is at storage slot 1, while the fallback function overwrites the storage slot 2.

In short, sending funds to this contract will never make you the actual owner.

#### Method Overwriting

```solidity

```

### Detection & Countermeasures

0. Caveat: these overrides appear in the sources but not in the bytecode.

1. The sources can be checked for duplicate definitions / polymorphism.

Since the whole point is to advertize for a functionality with the sources, they will be available.

### Resources

- [The Art of The Scam: Demystifying Honeypots in Ethereum Smart Contracts][article-honeypots], section `3.2.2`
- [Masquerading Code In Etherscan][video-masquerading-code]

## Fake Standard Implementation

### Evades

Etherscan's interpretation of proxy is fixed, it can easily be fooled.

### How

Contrary to the previous methods, this one doesn't use valid code from the standards.

It keeps the name / structure, but the code is actually different.

### Samples

Here's a fake EIP-1657 proxy implementation:

```solidity
function _getImplementation() internal view returns (address) {
    return
        StorageSlot
            .getAddressSlot(bytes32(uint256(keccak256("eip1967.fake")) - 1)).
            .value;
}
```

It doesn't use the standard slot for the implementation address:
Etherscan will show some irrelevant contract, giving the impression it is legit.

### Detection & Countermeasures

1. The bytecode selectors and implementation can be checked agains reference implementations

### Resources

- [Masquerading Code In Etherscan][video-masquerading-code]

[article-honeypots]: https://arxiv.org/pdf/1902.06976.pdf
[changelog-solidity-bugs]: https://github.com/ethereum/solidity/blob/develop/docs/bugs.json
[video-masquerading-code]: https://www.youtube.com/watch?v=l1wjRy2BYPg
