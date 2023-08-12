# Evading Detection In Web3

Smart contracts are core tools for scammers and protocol attackers to steal digital assets.

As there is now more scrutiny by both users and security tools, scammers are answering with deception.

There is a long history of malware detection and evasion growing side-by-side in the binary and web2 spaces.

It is very likely web3 will follow the same path: this repository will detail the latest developments.

## Malware Samples

Each technique is explained and illustrated with POC / real-world examples.

The goal is to build a labeled dataset of malicious code.

## TOC

- [Report](../report/web3-evasion-techniques.pdf)
- Samples:
  - [Spoofing Techniques](../samples/spoofing/README.md):
      - [Inheritance Overriding](../samples/spoofing/README.md#inheritance-overriding)
      - [Fake Implementation](../samples/spoofing/README.md#fake-standard-implementation)
  - [Morphing Techniques](../samples/morphing/README.md):
      - [Red Pill](../samples/morphing/README.md#red-pill)
      - [Evil Upgrades](../samples/morphing/README.md#evil-upgrades)
  - [Obfuscation Techniques](../samples/obfuscation/README.md):
      - [Hiding In Plain Sight](../samples/obfuscation/README.md#hiding-in-plain-sight)
      - [Hiding Behind Proxies](../samples/obfuscation/README.md#hiding-behind-proxies)
      - [Payload Packing](../samples/obfuscation/README.md#payload-packing)
  - [Poisoning Techniques](../samples/poisoning/README.md):
      - [Event Poisoning](../samples/poisoning/README.md#event-poisoning)
  - [Redirection Techniques](../samples/redirection/README.md):
      - [Selector Collisions](../samples/redirection/README.md#selector-collisions)
      - [Hidden Proxy](../samples/redirection/README.md#hidden-proxy)
