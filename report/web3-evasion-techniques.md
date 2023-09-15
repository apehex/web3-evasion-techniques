## CONTEXT

Prepared by the community of [Forta](https://forta.org/) as part of its[Threat Research Inititative](https://forta.org/blog/investing-in-applied-academic-threat-research/).

See [here](http://forta.org/join-tri) to apply to the TRi.

## DOCUMENT REVISION HISTORY

| VERSION           | MODIFICATION DATE | AUTHOR |
| ----------------- | ----------------- | ------ |
| Document creation | 01/08/2023        | Apehex |
| First draft       | 31/08/2023        | Apehex |

## CONTACTS

| CONTACT           | MAIL                      | ?             |
| ----------------- | ------------------------- | ------------- |
| Apehex            | apehex@protonmail.com     | t.me/apehex   |
| ?                 | ?                         | ?             |

# Overview

### Introduction

Smart contracts brought forth a new era of decentralized finance, with
increasing value being funneled into DEFI platforms. In turn, they have
become attractive tools for scammers and protocol attackers to steal
digital assets.

As there is growing scrutiny by both users and security tools, malicious
actors are answering with deception. To achieve their end goals, they
first have to appear legitimate and circumvent the security tools. This
involves specific tricks, which we refer to as \"evasion\" and are the
focus of this document.

Exploit detection mechanisms and evasive tactics have played a
relentless cat-and-mouse game in the binary and web spaces. Now, this
history can be analyzed to improve the current detection tools and
anticipate future threats in the web3 ecosystem. We will delve into the
code of each evasion technique, highlight their distinctive features and
propose countermeasures.

### Methodology

This report is grounded in both past and present research.

A literature review on traditional malware evasion forms the basis for
the study's taxonomy and framework. Studying these historical evasion
techniques gives insights into potential trends for the blockchain
ecosystem.

In addition to the lessons from the past, the study also incorporates
findings from current research in the web3 space. This research is
sourced from academic papers, conferences, tools, and watch groups
focused on blockchain security.

The report's practical aspect is backed by an analysis of selected smart
contract samples. These samples were chosen for two reasons: their
association with recent hacks and their ability to slip past detection
mechanisms, especially those of the [Forta
network](https://explorer.forta.network/).

Forta being a network of independent scanning agents, each of them is
free to implement a different approach. Since it is not bound by a
systemic choice of detection, the countermeasures are centered on each
evasion technique. Static, dynamic, hybrid, graph analysis are all
mentioned when it is relevant to a given target.

The analysis is meant as a reference guide for the development of future
bots on the Forta network. It will be a continuous feedback loop: the
report will be updated regularly as progress is made.

# Detection In Web3

## Data Sources {#ch:data-sources}

The data available for analysis depends on the execution stage. For
smart contracts, there are three main contexts: static, dynamic and
hybrid.

### Static Analysis

Outside of execution, the blockchain acts as a cold storage. In this
first context, the detection methods are called \"static analysis\".

#### Creation Metadata

The block and transaction objects hold a lot of data related to the
infrastructure of the blockchain. These informations, like
`block.difficulty` or `block.gaslimit`, can be
ignored when considering the smart contracts.

Other details like the contract's creator, the balance, the creation
timestamp and associated Ether provide a context to the whole analysis.

##### Contract's creator

The values `msg.sender` & `tx.origin` of the
transaction that created the contract tell us who did it!

This would be like having an IP: the addresses can be indexed to follow
the activity of known attackers.

In turn, bad actors can simply use new \"external owned accounts\" (EOA)
and redeploy / upgrade their contracts.

##### Creation Cost

The product of the gas price and gas used gives the cost of the smart
contract deployment.

This gas consumption is directly related to the intensity of the
processing involved. The historical data can be compared to a local
replay to determine if all the operations are accounted for in the
deployment code.

#### Compilation Metadata

Similarly to the traditional binaries, smart contracts are compiled into
bytecode. The context of the compilation is described in [a JSON
file](https://docs.soliditylang.org/en/v0.8.21/metadata.html).

The hash of these metadata may be appended to the bytecode of the
contract: this hash is actually an ID, which can be used to retrieve the
metadata and possibly the sources from a IPFS.

The settings used by the compiler are listed in the metadata. In
particular, the configuration of the optimizer is specified: the exact
binary output of the compilation will vary according to these settings.
When looking for patterns in the bytecode, these informations can be
used to adapt the patterns.

#### Bytecode

The main product of the compilation is the bytecode deployed on the
mainnet. It has several sections which can be parsed: OpenZeppelin wrote
an in-depth article on the [structure of smart contract
bytecode](https://gists.rawgit.com/ajsantander/23c032ec7a722890feed94d93dff574a/raw/a453b28077e9669d5b51f2dc6d93b539a76834b8/BasicToken.svg).

In itself, providing only the bytecode (and not the sources) is already
a layer of obfuscation. But it is always available and has all the logic
of the smart contract.

##### Function Selectors

Functions are not called by name, but by their selector. And the
selectors are hashes computed on the signature, like
`transfer(address,uint256)`:

```python
Web3.keccak(text='transfer(address,uint256)').hex().lower()[:10]
# '0xa9059cbb'
```

The list of selectors for all the function in the bytecode is [found in
its
hub](https://gists.rawgit.com/ajsantander/23c032ec7a722890feed94d93dff574a/raw/a453b28077e9669d5b51f2dc6d93b539a76834b8/BasicToken.svg).

Keeping an [updated index of all known
selectors](https://www.4byte.directory/signatures/) allows to go back
from hash to signature. It gives a lot of insight on the expected
behavior of a contract.

On the other hand, nothing prevents malicious actors from [naming their
functions as they
please](https://www.4byte.directory/signatures/?bytes4_signature=0xa9059cbb).

##### Function Bodies

Of course, execution requires instructions: the function bodies
implement the logic of the contract.

Just like binaries, they can be [reversed and analysed
statically](https://ethereum.org/en/developers/tutorials/reverse-engineering-a-contract/).
This opens the way for pattern matching and manual reviews of the code.

However, these processes can be hindered with code stuffing and other
techniques like packing (encryption, compression, etc).

##### Constructor

The smart contract constructor is not included in the bytecode deployed
on the blockchain. It is called once to initialize the contract state
and generate the final code that will sit on the blockchain.

So it can be found in the data of the [transaction that created the
contract](https://etherscan.io/tx/0xd66169d4a5feaceaf777b9949ad0e9bc5621a438846a90087e50a5d7b9b0ad1e).
Or in the source code, if provided (discussed below).

The constructor sets storage slots, which hold values that can totally
change the behavior of the contract. Admin privileges can at as a
backdoor and enable rug pulls for example.

Attackers will try and sneak data into the contract's state.

##### Opcode Sequence

[Bytecode can be interpreted as a
language](https://github.com/ethereum/evmdasm), giving a level of
abstraction to the analysis.

Indeed, different hex bytecodes can achieve the same result. It is
easier to get the high level logic from the sequences of opcodes than
from raw and specific hex chunks.

So the analysis mentioned above can be performed on opcodes, after
disassembling the binary. But disassembling is not an exact science and
it can be made even harder by classic techniques like
[anti-patterns](https://dl.acm.org/doi/10.1145/3395363.3404365).

#### Source code

First, source code is not always available: the blockchain itself
doesn't hold it, it has to be supplied to third party services, e.g.
block explorers.

With it, code review is humanly possible and reverse engineering becomes
easier. Sources help significantly to understand new attacks, but are
orders of magnitude too time consuming to provide live intelligence.

Also, Solidity can be misleading because of the many ambiguities and
[bugs](https://github.com/ethereum/solidity/blob/develop/docs/bugs.json).
Attackers will take advantage of the imprecision in the tools and the
limited resources of human reviewers.

### Dynamic Analysis

When a transaction is committed to the blockchain, the targeted smart
contract is executed. The actual behavior of the contract can be
witnessed first hand in this \"dynamic\" analysis, rather than infered.

#### Execution Metadata

First, the execution can be monitored on the blockchain nodes, with the
actual live data.

##### Transaction Origin

The records on the blockchain show every address that interacted with a
given contract. Just like the contract's creator, these addresses can be
saved and used to correlate different events on the blockchain.

Again, the attackers can answer with lateral movement: new EOAs, new
contract instances.

##### Transaction Recipient

Here the `to` field can only be the contract under
inspection. However it can call other addresses as part of its
processing, as seen below.

##### Transaction Gas

As mentioned earlier, gas is directly linked to the intensity of the
operations in the transaction.

Like CPU and RAM overloading, intensive computation can be the sign of
unwanted activity. Or it can be exploited for its own value: similarly
to CPU / GPU mining, gas can sometimes be redeemed by attackers.

Still, the blockchain always has its \"task manager\" open, so it is
hard to fly these tricks under the radar.

##### Transaction Value

High value transactions are not necessarily bad, but they are bound to
attract attention.

Bad actors will lower the noise levels by mixing / scattering the cash
flow for example.

#### Event Logs (Topics)

The events triggered by a given transaction are encoded in the logs,
more specifically in their topics and data fields. The type and
arguments of the events hold a lot of information by themselves. Also
the emitting address tells what external contracts were called if any.

Sometimes the presence of events is suspicious: in case of a high number
of transfers for example.

Other times their absence has implications: upgrading the implementation
of a proxy without triggering an `Upgraded` event is at least weird.

#### Execution Traces

Execution traces can be obtained either by replaying locally a
transaction or by querying a RPC node with tracing enabled.

##### Internal Function Calls

The flow of internal calls can be debugged locally, which may be the
most insightful analysis tool.

Just like traditional malware, smart contracts have means to evade
debugging: tests can be detected, the logic of the contract can be
cluttered\...

##### External Function Calls

A given smart contract can redirect the execution flow to external
addresses. `address.call` will segregate the contexts of the
contracts, while `address.delegatecall` allows the target
contract to modify the state of the origin address.

These external calls may be aimed at:

-   EOAs, for example to bait them into performing unsafe actions

-   legitimate contracts, to loan, launder, exploit, etc

-   malicious contracts, to split and layer the suspicious activity

Splitting the logic over several contracts is a way to make local
debugging harder too.

#### State Changes

State changes cover:

-   modification of the data in the storage slots

-   changes to the balance of the address

In particular, the storage of ERC contracts hold a lot of financial
information, which is valuable in itself: token holders, exchange rates,
administrative privileges, etc.

Because of the way data is [encoded and positioned in the storage
slots](https://docs.soliditylang.org/en/v0.8.17/internals/layout_in_storage.html),
there is no way to tell which slots are used without context. This
context can come from the transaction history or local debugging.

In any case, the design of the storage makes it stealthy.

### Hybrid Analysis

Zooming out from the perspective of a single smart contract, the
blockchain can be considered as a whole. This is a mix of the static
data across all addresses and the dynamic data generated across time and
addresses.

Rather than going over all the data sources again, this section offers
new angles from which they can be considered.

#### Statistics

The activity of a single address over time can be broken-down with
statistics.

They can combine static and dynamic analyses by bringing out which
functions / events are actually triggered and filtering out irrelevant
code.

It will add to the previous analyses and weight all the smart contract
actions with their frequency. This temporal profile can be compared with
other known contracts.

Independent transactions take perspective: are the interactions between
addresses repeated? Does the behavior of the contract change at any
point?

#### Graph Theory

Graph theory will perform the same type of analysis than statistics
while retaining more of the structure of the blockchain.

Indeed, the blockchain can be viewed as a graph with addresses as the
nodes and transactions as the vertices. The tricky part is to decide
which specific metric will be used on nodes and vertices.

Even simple labeling schemes, like the transaction amount, will help to
inspect the flow of cash & tokens.

Graph analysis can also be used to cluster the address space and show
the similarities between contracts.

To fool these meta indicators, attackers may add legitimate use &
traffic to their contracts.

#### Symbolic Fuzzing

Standard dynamic analysis will explore only a few execution paths during
fuzzing. Even the historical log of transactions will not show all the
possible interactions with a contract.

The goal of symbolic analysis is to test all the execution branches and
make the other detection techniques more exhaustive.

Symbolic testing has been adapted to Ethereum
[HoneyBadger](https://github.com/christoftorres/HoneyBadger) leverage
symbolic testing to explore all the execution paths.

This technique has known flaws: in particular, the number of conditional
branches can be exponantially increased, leading to [path
explosion](https://en.wikipedia.org/wiki/Path_explosion).

#### Machine learning

Machine learning can be used to achieve all of the above.

The ML models add a layer of abstraction that make the detection
inherently more robust to small variations and improvements from the
attackers. They will also find new samples even when they were not
exactly accounted for.

Tricky attackers may try and poison the models or flood the inputs with
irrelevant data.

## Taxonomy {#ch:taxonomy}

Having looked over the sources of data available, many avenues for
detection and evasion emerged. You can see them classified in figure
[2.1](#fig:taxonomy){reference-type="ref" reference="fig:taxonomy"}
below.

This taxonomy was made by analogy with the malware space: a good
overwiew can be found in [this survey from Applied
Sciences](https://www.mdpi.com/2076-3417/12/17/8482).

<figure id="fig:taxonomy">

<figcaption>Taxonomy of the detection &amp; evasion
techniques</figcaption>
</figure>

This categorization is very generic: since the evasion tactics leave
footprints on all the data, all the analysis tools have a role to play
in their detection.

So the specifics of the detection methods depend entirely on their
target: the rest of the document will focus on each evasion mechanism
and draw specialized indicators of compromise.

# Evasion Techniques

## Spoofing {#ch:known-spoofing}

Spoofing is the art of disguising malicious entities to appear common
and harmless.

### Fake Standard Implementation

#### Overview

Such contracts borrows the function & class names from industry
standards(OpenZeppelin, ERC, etc), but the code inside is actually
different.

The malicious contracts generally pretend to be:

proxies

:   but the implementation is either not used or different from the
    ERC-1967 proxy

tokens

:   but the transfer and / or approve functions behave differently than
    ERC-20 / 721 / 1155

#### Evasion Targets

block explorers

:   the interpretation of proxies is fixed, it can easily be fooled

users

:   few users actually check the code, having a valid front is enough

#### Samples

##### Fake EIP-1967 Proxy

The [standard EIP-1967](https://eips.ethereum.org/EIPS/eip-1967) has
pointers located in specific storage slots. In particular, slot number
`0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
holds the address of the logic contract.

These pointers can be kept null or target a random contract, while the
proxy actually uses another address.

A minimal example was given at DEFI summit 2023
[@video-masquerading-code]:

```solidity
function _getImplementation() internal view returns (address) {
    return
        StorageSlot
            .getAddressSlot(bytes32(uint256(keccak256("eip1967.fake")) - 1)).
            .value;
}
```

Etherscan will show some irrelevant contract, giving the impression it
is legit.

##### Fake ERC20 Token

Many phishing operations deploy fake tokens with the same symbol and
name as the popular ones.

For example, [this
contract](https://etherscan.io/address/0x5ed7ca349efc40550eecef4b288158fb2b9f12de#code)
is spoofing the USDC token. It was used in [this phishing
transaction](https://explorer.phalcon.xyz/tx/eth/0x7448178a8a03a0f1f298b697507f0e9172eacf1d32d422f48d0345c19c76eba3?line=33).

#### Detection & Countermeasures

Several sources can be monitored, depending on the standard that is
being spoofed:

Storage

:   comparing the target of `delegateCall` to the address in
    the storage slots of the standards

Events

:   changes to the address of the logic contract should come with an
    `Upgraded` event

Bytecode

:   the implementation of known selectors can be checked agains the
    standard's reference bytecode

### Overriding Standards Implementation

#### Overview

Like the previous technique
[1.1](#sec:fake-implementation){reference-type="ref"
reference="sec:fake-implementation"}, the goal is to have a malicious
contract confused with legitimate code.

It is achieved by inheriting from standardized code like `Ownable`,
`Upgradeable`, etc. Then, the child class overwrites key elements with:

redefinition

:   an existing keyword is defined a second time for the references in
    the child class only

polymorphism

:   an existing method can be redined with a slightly different
    signature

From the perspective of the source code, a single keyword like `owner`
can refer to different storage slot depending on its context. It is only
in the bytecode that a clear difference is made.

#### Evasion Targets

This technique is a refinment of the previous one: it will work on more
targets.

block explorers

:   blockchain explorers lack even more flexibility to detect these
    exploits

users

:   the source code is even closer to a legitimate contract

reviewers

:   the interpretation of the source code is subtle, and reviewing the
    bytecode is very time consuming

#### Samples

##### Attribute Overwriting

In section *3.2.2*, the paper [The Art of the
scam](https://arxiv.org/pdf/1902.06976.pdf) shows an example of
inheritance overriding with `KingOfTheHill` :

```solidity
contract KingOfTheHill is Ownable {
    address public owner; // different from the owner in Ownable

    function () public payable {
        if(msg.value > jackpot) owner = msg.sender; // local owner
        jackpot += msg.value;
    }
    function takeAll () public onlyOwner { // contract creator
        msg.sender.transfer(this.balance);
        jackpot = 0;
    }
}
```

In the modifier on `takeAll`, the `owner` points to the contract
creator. It is at storage slot 1, while the fallback function overwrites
the storage slot 2.

In short, sending funds to this contract will never make you the actual
owner.

#### Detection & Countermeasures

##### Source Code

While subtle for the human reader, tools can easily scan the sources for
duplicate definitions and polymorphism.

Since the whole point is to advertize for a functionality with the
sources, they will be available. However, the bytecode does not provide
any information on this class of evasion.

### Bug Exploits

#### Overview

A more vicious way to mask ill-intented code is to exploit bugs and EVM
quirks.

By definition, these bugs trigger unwanted / unexpected behaviors.

They can be:

EVM quirks

:   in particular, some operations are implied and not explicitely
    written

bugs

:   the Solidity language itself has [numerous
    bugs](https://github.com/ethereum/solidity/blob/develop/docs/bugs.json),
    depending on the version used at compilation time
    [@changelog-solidity-bugs]

They are usually leveraged in honeypots, where the attackers create a
contract that looks vulnerable. But the \"vulnerability\" doesn't work
and people who try to take advantage of it will lose their funds.

#### Evasion Targets

tools

:   honeypots are meants to trigger alerts in popular tools and mislead
    their users

reviewers

:   successfully used in honeypots, these tricks can fool security
    professional

#### Samples

All the samples below come from the paper [The Art of The Scam:
Demystifying Honeypots in Ethereum Smart
Contracts](https://arxiv.org/pdf/1902.06976.pdf)
[@paper-art-of-the-scam].

##### Impossible Conditions

Attackers can craft a statement that will never be true.

A [minimal example](https://www.youtube.com/watch?v=4bSQWoy5a_k) was
given at DEFI summit 2023 by Noah Jelic [@video-hacker-traps]:

```solidity
function multiplicate() payable external {
    if(msg.value>=this.balance) {
        address(msg.sender).transfer(this.balance+msg.value);
    }
}
```

This gives the illusion that anyone may-be able to withdraw the
contract's balance.

However, at the moment of the check, `this.balance` has
already been incremented: it can never be lower than
`msg.value`.

In reality, the contract would have exactly the same behavior if the
`multiplicate` function was empty.

##### Skip Empty String Literal

The Solidity encoder skips empty strings: the following arguments in a
function call are shifted left by 32 bytes.

In the following snippet, the call to `this.loggedTransfer`
ignores `msg.sender` and replaces it with `owner`.
In other words the sender cannot actually receives the funds, it is a
bait.

```solidity
function divest ( uint amount ) public {
    if (investors[msg.sender].investment == 0 || amount == 0) throw;
    investors[msg.sender].investment -= amount;
    this.loggedTransfer(amount, "", msg.sender, owner);
}
```

##### Type Deduction Overflow

The compiler uses type deduction to infer the the smallest possible type
from its assignment. For example, the counter is given the type
`uint8`, and the loop actually finishes at 255 instead of
`2*msg.value`:

```solidity
if (msg.value > 0.1 ether) {
    uint256 multi = 0;
    uint256 amountToTransfer = 0;
    for (var i=0; i < 2*msg.value; i++) {
        multi = i * 2;
        if ( multi < amountToTransfer ) {
            break;
        }
        amountToTransfer = multi;
    }
    msg.sender.transfer(amountToTransfer);
}
```

Since the caller must have sent `0.1 ether` he loses money.

##### Uninitialised Struct

Non initialized structs are mapped to the storage. In the following
example, the struct `GuessHistory` overwrites the \"private\"
random number.

```solidity
contract GuessNumber {
    uint private randomNumber = uint256(keccak256(now)) % 10+1;
    uint public lastPlayed;
    struct GuessHistory {
        address player;
        uint256 number;
    }
    function guessNumber (uint256 _number) payable {
        require (msg.value >= 0.1 ether && _number <= 10);
        GuessHistory guessHistory;
        guessHistory.player = msg.sender;
        guessHistory.number = _number ;
        if (number == randomNumber)
            msg.sender.transfer(this.balance);
        lastPlayed = now;
    }
}
```

in the check `(number == randomNumber)`, the
`randomNumber` is now an address which is highly unlikely to
be lower than 10.

#### Detection & Countermeasures

testing

:   symbolic testing & fuzzing will show the actual behavior; the issue
    is rather to formulate what is expected for any arbitrary contract

CVEs

:   known vulnerabilities can be identified with pattern matching; in
    traditional malware detection, [YARA
    rules](https://yara.readthedocs.io/en/stable/writingrules.html) are
    written

There's a tool aimed specifically at detecting honeypots,
[HoneyBadger](https://github.com/christoftorres/HoneyBadger).

### Sybils

#### Overview

Much like social networks, the blockchain is made of interconnected
users. Their activity in and out of the blockchain gives weight to a
project.

So scammers could:

-   creates bots and enroll people to build a legitimate history on
    their contracts

-   create a normal service to hijack it later

Bots have been leveraged to generate trading activity for several
tokens: DZOO, oSHIB, oDOGE, GPT, and SHIBP at least. For instance, the
[case study of the DZOO
campaign](https://forta.org/blog/attack-deep-dive-soft-rug-pull/) shows
how it used bot EOAs to pump the price of its token.

These techniques are an [active area of
research](https://en.wikipedia.org/wiki/Sybil_attack) and would require
an entire study. They will not be covered in this document.

## Morphing {#ch:known-morphing}

Morphing contracts change their behavior depending on the context. In
particular they replicate benign functionalities when they're under
scrutiny.

### Red-Pill

#### Overview

The red-pill technique detects simulation environment to disable its
exploits upon scrutiny.

The contract detects simulation environments by checking:

globals

:   these variables have special values in test environments:

    -   `block.basefee`: `0`

    -   `block.coinbase`:
        `0x0000000000000000000000000000000000000000`

    -   `tx.gasprice`: large numbers, higher than
        `0xffffffffffffffff`

Then it triggers legitimate code in simulation contexts and malicious
code on the mainnet.

#### Evasion Targets

##### Wallets

Wallets often perform a simulation of the transaction before committing.
The whole point of this method is to pass these tests and bait the
end-user.

##### Security Tools

Automatic tools will likely not fuzz the coinbase or other global
variables. So the dynamic analysis may follow the \"harmless\" branch
and not inspect the actual behavior of the contract on the mainnet.

On the other hand these unusual checks stand out when reviewing the
code.

#### Samples

The contract `FakeWethGiveaway` mentioned in [@article-red-pill] checks
the current block miner's address:

```solidity
function checkCoinbase() private view returns (bool result) {
    assembly {
        result := eq(coinbase(), 0x0000000000000000000000000000000000000000)
    }
}
```

When null (test env), it actually sends a reward:

```solidity
bool shouldDoTransfer = checkCoinbase();
if (shouldDoTransfer) {
    IWETH(weth).transfer(msg.sender, IWETH(weth).balanceOf(address(this)));
}
```

Otherwise, on the mainnet, it just accepts transfers without doing
anything.

#### Detection & Countermeasures

opcodes

:   looking for unusual opcodes: typically `block.coinbase`

fuzzing

:   the transactions can be tested with blank data and compared with
    results behavior on data

### Lateral Movement

#### Overview

After being detected, attackers can either improve their scheme\... Or
just rinse and repeat! This is a very basic and widespread method.

More specifically, attackers can just:

-   create new EOA addresses

-   deploy several instances of their contracts

#### Evasion Targets

##### Block Explorers

Many block explorers allow users to [tag
addresses](https://etherscan.io/address/0x00000c07575bb4e64457687a0382b4d3ea470000),
especially scams.

This is a manual process, so new addresses have to be discovered and
tagged, even exact duplicates.

##### User Tools

This simple trick will get attackers past the blacklists of wallets and
firewalls, for a time.

#### Samples

Fake tokens have been deployed in numerous phishing scams. This
particular USDT variant has [412 siblings in
ETH](https://etherscan.io/find-similar-contracts?a=0xA15B3d31F1f5D544933C35eB00568Ead238B4f63&m=low&ps=25&mt=1).

#### Detection & Countermeasures

##### Bytecode

Signatures of the attacking contract can be indexed in a database, so
that when a new sample surfaces it will be instantly found.

##### Graph Analysis

The secondary addresses will most likely interact with their siblings /
parent at some point. In particular the collected funds may be
redirected to a smaller set of addresses for cashout.

Graph analysis would propagate its suspicions from parent to child
nodes.

### Logic Bomb

#### Overview

As [Wikipedia states it](https://en.wikipedia.org/wiki/Logic_bomb): a
logic bomb is a piece of code intentionally inserted into a software
system that will set off a malicious function when specified conditions
are met. These conditions are usually related to:

-   the execution time: it can check the `block.timestamp` or
    `block.number` for example

-   the execution environment: actually, the technique from section
    [2.1](#sec:red-pill){reference-type="ref" reference="sec:red-pill"}
    is a subclass of the logic bomb

-   patterns in the input data: typically, the execution can depend on
    the address of the sender

Some logic bombs are meant to counter symbolic testing. These bombs nest
conditional statements without actually caring about the tests
themselves. The simple chaining of conditions has the effect of
exponantially increasing the number of execution paths. In the end, it
may overload the testing process.

#### Evasion Targets

##### User Tools

Just as the red-pill bypassed wallets
[2.1](#sec:red-pill){reference-type="ref" reference="sec:red-pill"},
logic-bombs may fool other tools.

For example, the past transactions listed in a block explorer may give a
false sense of security. There is no guarantee that similar calls will
result in the same results in a different context (different sender,
later time, etc).

Honeypots tend to fail once there is enough transaction records to show
that the vulnerability is not exploitable. However, a malicious smart
contract may only need to perform it's evil actions in a fraction of the
transactions it processes. These failed attempts could be flooded in
attractive promises of gain as shown by other past transactions.

##### Security Tools

Most likely the fuzzing of security tools will remain in the space where
the malicious functionalities are disabled. [Path
explosion](https://en.wikipedia.org/wiki/Path_explosion) is also
designed specifically to break the symbolic analysis of code in general.

#### Samples

To our knowledge, this technique is a speculation and has not yet been
witnessed in Web3.

#### Detection & Countermeasures

##### Fuzzing

Here, the probability of detecting such tricks depends of the extent of
the input space covered by the tests. Security tools should fuzz the
metadata of the transactions too.

##### Opcodes

Scanning the bytecode for unusual opcodes may be enough to uncover
logic-bombs.

## Obfuscation {#ch:known-obfuscation}

Obfuscation is the process of making (malicious) code hard to find and
understand.

### Hiding In Plain Sight

#### Overview

By stacking dependencies, the scammer grows the volume of the source
code to thousands of lines.

99% of the code is classic, legitimate implementation of standards.

And the remaining percent is malicious code: it can be in the child
class or hidden inside one of the numerous dependencies.

This technique is the most basic: it is often used in combination with
other evasion methods.

#### Evasion Targets

##### Code Reviewers

A single line can compromise the whole codebase, so the reviewing
process is very laborious and slow. Attackers stuff the code to
overwhelm security auditors with the sheer volume of code.

##### Security Tools

Unrelated data also lowers the efficiency of ML algorithms: adding valid
code will increase the chances of the contract to be classified as
harmless.

#### Samples

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

#### Detection & Countermeasures

##### Bytecode

The size of the bytecode is a low signal, but:

-   it is easy to detect, with certainty

-   the codebase is always large when this technique is used

-   not all contracts are bulky, some can be filtered out

The tricky part is to choose a relevant threshold on the size of the
code.

##### Execution Traces

The proportion of the code actually used can be computed by replaying
transactions.

It is important to *replay the past transactions* and **not** perform
new tests. Indeed, testing all the functions would skew the statistics
on mainnet usage.

### Hiding Behind Proxies

#### Overview

Malicious contracts simply use the EIP-1967 [@eip-1967] specifications
to split the code into proxy and logic contracts.

#### Evasion Targets

Etherscan

:   the proxy contracts are often standard and will be validated by
    block explorers

users

:   most users rely on block explorers to trust contracts

reviewers

:   the source code for the logic contract may not be available:
    reversing and testing EVM bytecode is time consuming

#### Samples

This [phishing contract]() has its [proxy contract verified]() by
Etherscan.

While its logic contract is only available as [bytecode]().

#### Detection & Countermeasures

Since it comes from Ethereum standards, this evasion is well-known and
easy to detect.

However it is largely used by legitimate contracts, it is not conclusive
by itself.

proxy patterns

:   proxies can be identified from the bytecode, function selectors,
    storage slots of logic addresses, use `delegateCall`, etc

block explorer

:   the absence of verified sources is a stronger signal (to be balanced
    according to contract activity and age)

bytecode

:   the bytecode of the logic contract can still be further analyzed

### Hidden State

#### Overview

The used storage slots are not explicitely listed: data can be slipped
in the huge address space of the storage without leaving a public
handle.

initialization

:   the constructor code is not in the available bytecode, it can fill
    slots without raising any flag

delegation

:   a delegate contract could also modify the state

#### Evasion Targets

Actually, this method is effective against all the detection agents:

everyone

:   the data is not visible in the sources nor in the bytecode

#### Samples

The contract can be entirely legitimate, and compromising the storage is
enough.

It has been [demonstrated by Yoav
Weiss](https://www.youtube.com/watch?v=l1wjRy2BYPg) with a [Gnosis
Safe](https://github.com/safe-global/safe-contracts). The constructor
injected an additional owner into the storage, allowing a hidden address
to perform administrative tasks.

#### Detection & Countermeasures

##### Gas consumption

Storing data on the blockchain is a [very costly
operation](https://github.com/wolflo/evm-opcodes/blob/main/gas.md). If
nothing else, changes to the storage can be detected through gas
consumption, especially when writing to empty / unsued slots.

### Payload Packing

#### Overview

For software executables, packing applies a combination of encryption /
encoding / compression on a binary. These operations are reversed during
execution. Originally, the purpose was to spare secondary memory and
make software more compact.

This motivation [still stands on the
blockchain](https://medium.com/joyso/solidity-compress-input-in-smart-contract-d9a0eee30fe0),
where processing and storage are especially costly. Several schemes for
compression are being studied, even on the [EVM
level](https://eips.ethereum.org/EIPS/eip-3772).

These techniques could also be leveraged to harden contracts against
reverse-engineering. Both data and / or code can be packed, by the
contract itself, a proxy or a web app.

Unpacking can be performed either by the contract itself or by a proxy.

#### Evasion Targets

##### Block Explorers

With the input data packed in the transaction history, making sense of
past events is harder.

##### Security Tools

All the known patterns and signatures will fail on the packed data.

##### Security Reviewers

Interacting with a packed contract may require additional layers of
(un)packing to handle the input and outputs. If the (byte)code is
packed, static analysis will be significantly slowed too.

#### Samples

To our knowledge, this technique is a speculation and has not yet been
witnessed in Web3.

#### Detection & Countermeasures

##### Entropy

Usually, these obfuscation schemes can be detected by measuring the
entropy. This is harder to implement in this context because the
blockchain makes extensive use of hashing algorithms, which are high
entropy.

## Poisoning {#ch:known-poisoning}

Poisoning techniques hijack legitimate contracts to take advantage of
their authority and appear trustworthy.

### Event Poisoning

#### Overview

Events have the underlying implication that some change happened and the
blockchain state evolved.

It is actually possible to trigger events without their side effects.
For instance, by setting the amount to 0 on the ERC20
`tranfer` it is possible to trigger `Transfer`
events without moving any token!

Actually, all standards and events could potentially be hijacked.

#### Evasion Targets

##### Users

Many users don't double check events, especially not when they come from
well-known tokens / contracts.

#### Samples

In [this batch
transaction](https://explorer.phalcon.xyz/tx/polygon/0x8a5f75338bfbf78b0969cdf5bacfe24c65e703ea94b430c470193b3d2a094441?line=1),
the scammer pretended to send USDC, DAI and USDT to 12 addresses. The
attacker baited users by coupling two transfers:

-   a transfer of 0 amount of a popular token, say USDT

-   a transfer of a small amount of a fake token, with the same name and
    symbol

The Forta network [detected the transfer events of null
amount](https://explorer.forta.network/alerts?limit=20&sort=desc&text=&txHash=0x8a5f75338bfbf78b0969cdf5bacfe24c65e703ea94b430c470193b3d2a094441).

#### Detection & Countermeasures

##### Event Logs

These scams are easily uncovered by parsing the transaction logs. They
contain the list of events, with arguments that specify what happened.

The idea is to define constraints on the arguments of all the standard
events. For example, valid ERC20 `Transfer` events would have a
constraint *strictly greater than zero* on the `amount` argument.

Then these constraints would be checked on the live transactions.

Ideally, these checks should be performed beforehand, by the contracts
behind the event emission.

### Living Off The Land

#### Overview

Living off the land means surviving on what you can forage, hunt, or
grow in nature. For malware, it means using generic, OS-level, tools to
compromise a target.

For smart contracts, it could mean:

-   taking advantage of callbacks to run malicious code

-   using factory contracts to deploy evil variants

The more complex the protocol, the more facilities they will offer for
attackers.

#### Evasion Targets

Potentially, this category of evasion could bypass many layers of
defense: since a significant part of the exploitation runs in legitimate
contracts, their authority will most likely escape detection.

#### Samples

To our knowledge, this technique is a speculation and has not yet been
witnessed in Web3.

#### Detection & Countermeasures

## Redirection {#ch:known-redirection}

These techniques reroute the execution flow from legitimate functions to
hidden and malicious code.

### Hidden Proxy

#### Overview

Hidden proxies redirect the execution to another contract just like
standard proxies, except that they pretend not to.

Apart from this redirection trick, the rest of the contract code can be
anything: a token, ERC-1967 proxy, etc. There are two cases:

-   the contract inherits from a reference proxy contract: the expected
    implementation will serve as a bait and another logic contract is
    used in practice

-   otherwise the delegate contract adds hidden functionalities, like a
    backdoor

Just like proxies, a common way to achieve this is to performs
`delegateCall` on any unknown selector, via the fallback function. In
its simplest form, the fallback would just use another address for the
logic contract. More sophiscated attackers will chain proxies or combine
this trick with other evasion techniques like
[1.2](#sec:overriding-implementation){reference-type="ref"
reference="sec:overriding-implementation"}.

The target address can be hardcoded or passed as an argument, making it
stealthier.

#### Evasion Targets

This technique stacks another layer of evasion on top those mentioned in
[3.1](#sec:hiding-in-plain-sight){reference-type="ref"
reference="sec:hiding-in-plain-sight"}.

##### Block Explorers

Block explorers can detect standard proxy patterns and show the
corresponding implementation contract. In this context, the shown
implementation is not used and the explorers are actually misinforming
their users.

##### Security Tools

The malicious code is not directly accessible and the tools may end up
analysing the legitimate implementation instead.

The actual logic address can be obfuscated or even missing from the
bytecode. Transaction tracing is the most reliable inspection tool in
this case, and it is not always available.

#### Samples

A malicious fallback can be inserted into an expensive codebase:

```solidity
fallback () external {
	if (msg.sender == owner()) {
		(bool success, bytes memory data) = address(0x25B072502FB398eb4f428D60D01f18e8Ffa01448).delegateCall(
			msg.data
		);
	}
}
```

#### Detection & Countermeasures

This attack scheme will most likely involve masquerading code: the
indicators mentioned in
[3.1](#sec:hiding-in-plain-sight){reference-type="ref"
reference="sec:hiding-in-plain-sight"} provide a basis for the
detection.

##### Tracing

The address of the hidden implementation can be found in the trace logs.

##### Transaction History

Comparing the results of transactions over time may show significant
differences and highlight a change in implementation.

### Selector Collisions

#### Overview

Because the function selectors are only 4 bytes long, it is easy to find
collisions.

When a selector in the proxy contract collides with another on the
implementation side, the proxy takes precedence.

This can be used to override key elements of the implementation.

#### Evasion Targets

tools

:   this subtle exploit evades most static analysis

reviewers

:   the sources don't show the flow from legitimate function to its
    malicious collision

#### Samples

As [Yoav Weiss showed at DSS
2023](https://www.youtube.com/watch?v=l1wjRy2BYPg), this harmless
function:

```solidity
function IMGURL() public pure returns (bool) {
    return true;
}
```

Collides with another function:

```python
Web3.keccak(text='IMGURL()').hex().lower()[:10]
# '0xbab82c22'
Web3.keccak(text='vaultManagers(address)').hex().lower()[:10]
# '0xbab82c22'
```

And this view is used to determine which address is a manager, e.g. it
is critical:

```solidity
mapping (address=>bool) public vaultManagers;
```

#### Detection & Countermeasures

The collisions can be identified by comparing the bytecodes of proxy and
implementation:

selectors

:   the hub section of the bytecode has the list of selectors

debugging

:   dynamic analysis will trigger the collision; still it may not have
    an obviously suspicious behavior

The article [deconstructing a Solidity
contract](https://blog.openzeppelin.com/deconstructing-a-solidity-contract-part-i-introduction-832efd2d7737)
has a [very helpful
diagram](https://gists.rawgit.com/ajsantander/23c032ec7a722890feed94d93dff574a/raw/a453b28077e9669d5b51f2dc6d93b539a76834b8/BasicToken.svg).
