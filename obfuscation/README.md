# Obfuscation Techniques

Make the malicious code hard to find / understand.

## Hiding In Plain Sight

### Evades

Here, the goal is to overwhelm source code reviewers with the sheer volume of code.

It also lowers the efficiency of ML algorithms.

### How

By stacking dependencies, the scammer grows the volume of the source code to thousands of lines.

99% of the code is classic, legitimate implementation of standards.

And the remaining 1% is malicious code, hidden inside one of the numerous dependencies for example.

### Samples

Hidden among 7k+ lines of code:

```solidity
// no authorization modifier `onlyOwner`
function transferOwnership(address newOwner) public virtual {
    if (newOwner == address(0)) {
        revert OwnableInvalidOwner(address(0));
    }
    _transferOwnership(newOwner);
}
```

### Detection & Countermeasures

1. The proportion of unused code can be leveraged from the transaction history.

### Resources

- [Masquerading Code In Etherscan][video-masquerading-code]

## Stowaway Storage

### Evades

Totally bypasses source & bytecode analysis by humans & tools.

### How

At the construction / initialization, data can be put in storage at arbitrary slots.

### Detection & Countermeasures

## Hiding Behind Proxies

### Evades

- Etherscan code verification
- source code reviews

### How

Keeping the sources closed by only exposing a proxy contract.

## Payload Packing

### Evades

Pattern matching on the bytecode.

### How

Encryption / encoding / compression can be leveraged to make malicious code unreadable.

### Detection & Countermeasures

1. Scanning for high entropy data

[video-masquerading-code]: https://www.video.com/watch?v=l1wjRy2BYPg