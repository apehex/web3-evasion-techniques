# Evading Detection In Web3

Smart contracts are core tools for scammers and protocol attackers to steal digital assets.

As there is now more scrutiny by both users and security tools, scammers are answering with deception.

There is a long history of malware detection and evasion growing side-by-side in the binary and web2 spaces.

It is very likely web3 will follow the same path: this repository will detail the latest developments.

## TOC

- [Faking Techniques](../faking/README.md):
    - [Inheritance Overriding](../faking/README.md#inheritance-overriding)
    - [Fake Implementation](../faking/README.md#fake-standard-implementation)
- [Morphing Techniques](../morphing/README.md):
    - [Red Pill](../morphing/README.md#red-pill)
    - [Evil Upgrades](../morphing/README.md#evil-upgrades)
- [Obfuscation Techniques](../obfuscation/README.md):
    - [Hiding In Plain Sight](../obfuscation/README.md#hiding-in-plain-sight)
    - [Hiding Behind Proxies](../obfuscation/README.md#hiding-behind-proxies)
    - [Payload Packing](../obfuscation/README.md#payload-packing)
- [Poisoning Techniques](../poisoning/README.md):
    - [Event Poisoning](../poisoning/README.md#event-poisoning)
- [Redirection Techniques](../redirection/README.md):
    - [Selector Collisions](../redirection/README.md#selector-collisions)
    - [Hidden Proxy](../redirection/README.md#hidden-proxy)

## Malware Samples

Each technique is explained and illustrated with POC / real-world examples.

The goal is to build a labeled dataset of malicious code.

## TODO

- requires to fetch contract bytecode: slower agent?
- online fuzzing & symbolic parsing?
- bot context:
  - how to request source code?
  - how to fetch transaction history?
- implement indicators as a lib?
  - when the input data (contract source code) is not accessible for the bot?
- YARA style reference implementations / signatures?
- from Web2:
  - living off the land (memory / network)
  - injections (infecting common files)
- report a hack / scam:
  - https://www.chainabuse.com/report
- how does detection impact scammers?
  - (morphing / lateral mvt necessary?)
- alternative taxonomy:
  - evading users (faking contracts)
  - evading reviewers (code volume, subtle exploits etc)
  - evaing tests (tx simulation)
  - evading tools (etherscan code review, forta, etc)
