## TODO

### Plan

- review
  - malware evasion + detection
  - all web3 conferences, papers, articles 2023
- samples
  - rekt / chainabuse hacks: filters
  - Forta alerts
- community
- agent
  - online fuzzing: cf attack simulation agent
  - cluster addresses in transaction hisotry
  - ml model to analyse bytecode
  - YARA ?
  - how to know about the samples that escaped detection?

### // Web3

- living off the land (memory / network)
- injections (infecting common files)

### Questions

- too many RPC requests??

- can I suppose the reader has the basics of malware detection?
  - apply each concept to the evasion problem
  - leave the basics at the end of the report ? stuff like defining signature based malware detection etc
- level of detail for the detection:
  - principle?
  - code snippet
- alternative taxonomy:
  - evading users (faking contracts)
  - evading reviewers (code volume, subtle exploits etc)
  - evaing tests (tx simulation)
  - evading tools (etherscan code review, forta, etc)
- switch order of the parts => detection before evasion?
- how does detection impact scammers?
  - (morphing / lateral mvt necessary?)
- a mix of "normal" behaviors can be malicious: it's the mix that matters
  - normal token + normal proxy in a single contract is suspicious
  - identify each class of contracts independently
  - if a contract is seen as 90% token and 90% proxy it is abnormal
- NORMAL behavior is key:
  - what is normal FOR a type of contract
  - sthg normal to a proxy is suspicious on a token
