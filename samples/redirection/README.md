# Redirection Techniques

Reroute the incoming calls to unexpected functions.

## Selector Collisions

### Evades

This subtle 

### How

Because the function selectors are only 4 bytes long, it is easy to find collisions.

When a selector in the proxy contract collides with another on the implementation side, the proxy takes precedence.

This can be used to override key elements of the implementation.

### Samples

As shown in [the talk by Yoav Weiss at DSS 2023][video-masquerading-code]:

```solidity
function IMGURL() public pure returns (bool) {
    return true;
}
```

This function has the same selector as `keccak("vaultManagers(address)")[0:4]`.

## Hidden Proxy

### Evades

This technique allows scammers to verify their contracts will dodging source code reviews.

### How

The contract performs `delegateCalls` on any unknown selector.

The target address can be hardcoded, making it 

In the end, the exposed functionalities are not meaningful, the logic is located at a seemingly unrelated address.

### Samples

```solidity
fallback () external {
    if (msg.sender == owner()) {
        (bool success, bytes memory data) = address(0x25B072502FB398eb4f428D60D01f18e8Ffa01448).delegateCall(
            msg.data
        );
    }
}
```

### Resources

- [Masquerading Code In Etherscan][video-masquerading-code]

[video-masquerading-code]: https://www.video.com/watch?v=l1wjRy2BYPg
