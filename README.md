

# [Multidata Network Whitepaper](https://multidata.ai) 

Multidata Oracle is specifically designed for storing and efficiently updating a large number of on-chain price quotes. Utilizing logarithmic delta encoding for price updates, this solution maximizes both storage efficiency and cost-effectiveness.

With decentralization at its core, the deterministic quoting approach enables the integration of techniques such as threshold signatures. By allowing multiple parties to construct price feeds off-chain and deliver them on-chain using a single verifiable signature, Multidata Oracle achieves significant gas savings compared to other oracle protocols. The critical role of off-chain logic in enhancing the system's overall efficiency and performance cannot be underestimated, as it enables more streamlined and cost-effective operations.



![](https://i.imgur.com/r1ojUNw.png)




*Currently, a beta version of the oracle quotes 1000+ assets on:*
* Multidata
* Arbitrum
* Aurora
* Avalanche
* BitTorrent Chain
* Boba Network
* Boba Network
* BNB Chain
* CELO
* CLV Chain
* Cronos Chain
* Dogechain
* Gnosis Chain
* Moonriver
* Moonbeam
* HECO Chain
* Klaytn
* OKC
* Polygon
* Fantom
* Optimism
* Oasis
* Harmony
* Syscoin
* [Ethereum](https://etherscan.io/address/0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA) Chainlink-compatible backup oracle on Ethereum mainnet


#### Stablecoins
```
USDC, USDT, TUSD, BUSD, sUSD, DUSD, USDN, DAI, FEI, UST, HUSD, mUSD, USDP
```

#### Tokens
```
WBTC, WETH, ORN, BOND, UMA, YAM, DNT, STAKE, BAT, MANA, YFI, 1INCH, ARMOR, DPI, NMR, VSP, KP3R, UNI, REPv2, SOCKS, CREAM, BADGER, BOR, REN, PICKLE, OXT, COVER, WOO, TRU, FTM, CVX, NU, LINK, BZRX, POND, HEGIC, LDO, GNO, SUSHI, MATIC, AAVE, OGN, ANKR, FRAX, KEEP, xSUSHI, MPH, AKRO, SXP, DUCK, SHIB, OCEAN, MKR, CRO, ADX, BAND, LRC, SNX, WOOFY, RGT, renFIL, CRV, ZRX, renBTC, ENJ, RARI, ANT, ALPHA, MM, MTA, CEL, SFI, PERP, BAL, COMP, GRT, OMG, ALCX, KNC, INJ, ANY, SYS
```

#### Compound tokens (cTokens)
```
cWBTC, cUNI, cCOMP, cLINK, cUSDT, cDAI
```
#### Yearn Vaults
```
yvCurve-HUSD, yvCurve-UST, yvCurve-USDN, husd3CRV, yvLINK, yvCurve-BUSD, yvUSDT, yvCurve-3pool, ust3CRV, yvBOOST, yvWBTC, yvCurve-FRAX, yv1INCH, yvYFI, TUSD3CRV-f, yvSNX, yvUNI, yvWETH, yvsUSD, yvCurve-TUSD
```
#### Sushiswap LP tokens
```
SLP: WETH-USDT, USDC-WETH, WBTC-WETH, UMA-WETH, YFI-WETH, WETH-yveCRV, 1INCH-WETH, COMP-WETH, WETH-CRV, REN-WETH, SUSHI-WETH, SNX-WETH, BAND-WETH, DAI-WETH, LINK-WETH, AAVE-WETH, UNI-WETH, sUSD-WETH, renDOGE-WETH
```
#### Uniswap V2 LP tokens
```
WETH-USDT, WETH-renBTC, USDC-WETH, WBTC-WETH, renZEC-WETH, WETH-AMPL, HEGIC-WETH, YFI-WETH, STAKE-WETH, WETH-CRV, SNX-WETH, WETH-renFIL, WETH-RARI, KP3R-WETH, UMA-WETH, yvBOOST-WETH, FEI-WETH, DAI-WETH, MKR-WETH, COMP-WETH, AAVE-WETH, LINK-WETH, DUCK-WETH, UNI-WETH
```
#### 3Pool LP tokens (3crv)
```
usdn3CRV, husd3CRV, ust3CRV
```
#### Stocks, Bonds, Currencies, Commodities on Gnosis Chain

Contract address [`0xA0D41dA88Cce5404D407D549eB68730F78b6Be4e`](https://blockscout.com/xdai/mainnet/address/0xA0D41dA88Cce5404D407D549eB68730F78b6Be4e/transactions)

#### Sources of data
```
Binance, Huobi, Kraken, BitMart, Hotbit, MEXC, OKX, Coinbase, Uniswap V2, Uniswap V3, Sushi, Compound, Curve
```


## Specification

The chosen solution involves coordinating participants and providing intermediate data storage through a side network. Benefits of using a side network include:

- No central point of communication or failure
- DDoS protection for participants
- Easy network switching in case of complete network failure or DoS
- No reliance on the side network's trustworthiness



## Flow

### Adding Assets
To enable querying and updating, assets must be added to the contract. This process is simple and uses regular quoting mechanics to obtain initial prices. Access control is the same as for updating quotes, but other governance strategies can be implemented. Multiple on-chain oracles with different precision/gas cost trade-offs may exist.

### Quoting

The quoting process in oracle solutions involves the deterministic interpretation of a set of rules, allowing any party to obtain the same result regardless of calculation time or party-specific conditions. Each rule typically combines data feeds from the most reliable sources of liquidity for a specific asset.

A key idea behind this quoting approach is to eliminate reliance on any single party, such as centralized exchanges or decentralized exchanges. Additionally, it does not assume that major stablecoin prices are close to 1. All data feeds are implemented with built-in flash loan resistance, addressing a common vulnerability in oracle solutions. This approach fosters decentralization and enhances the robustness of the oracle system.

### Multiparty Operation

At present, multiparty ECDSA is being considered as a solution for decentralization, since ECDSA verification is relatively inexpensive on the Ethereum mainnet. Auxiliary protocol message exchanges can be conducted trustlessly through more affordable networks, adding transparency and robustness to the system. This approach provides a decentralized and secure method for updating and verifying information within oracle systems.


### On-Chain Querying

To obtain the price of an asset, only one function with an intuitive interface needs to be called. The interpretation of the price depends on the price format specified by the quoting rules. The oracle protocol itself is format-agnostic and flexible, allowing for seamless integration and adaptation to various use cases.

///
///

## Components

### Oracle contract

The contract is quite minimalistic. For each asset, it keeps the price at some moment in the past, and the difference (delta) to calculate the last known price on the fly. It is much cheaper to store a batch of differences than to update the prices one by one.
Additionally, the contract exposes several view functions to support the updater library operation (see below).

### Updater library

Since the contract exposes quite a low-level data model (as well as some other primitives), the approach to updating the quotes can be quite flexible and can be changed on the fly. It will not require the contract redeployment as quote updating is coded off-chain in a form of a library. The idea is simple: if the difference between the base price and the current price can be represented by a small delta, use the delta. Otherwise, set the base price to the current price.
Because a delta is valid only for a particular base price, we must ensure that the base price is not updated concurrently. To save storage read calls a simple 64-bit checksum is used. This task is also handled by the library.

### Quoting library

A set of quoting rules is expressed in a configuration file. A quoting library processes the rules and constructs a tree of objects called price feeds. Here we take a modular approach to decompose a quoting task as a tree of ready-made price feeds, e.g. UniswapV3Feed.

There may be subtleties in handling one or another price source. To keep the quoting approach deterministic, all these subtleties must be specified and handled by the parties in the same way.
They are not allowed to expose any non-determinism or randomness.
Currently, there is no formal specification of quoting rules and feeds. However, it can easily be derived from the existing implementation. We are assuming that in the future there will be alternative implementations to facilitate decentralization and reliability.

### Daemon

There is the last piece to glue things together - the code that pulls data from quoting library and feeds it into the contract using the updater library. This code can be run as a Unix daemon or as a Docker container.

### Chainlink Compatibility contract

We provide Chainlink-compatible aggregator (`IChainlinkAggregatorV2V3Interface`) for every quoted asset via special contract which is able to generate numerous aggregators in a gas-efficient way.



### Threat model

1. At least `M = 2 * N // 3 + 1` participants are honest, non-compromised and operational.
2. A mainnet (the network which hosts the oracle contract) is reasonably operational, live, and protected from deep reorganizations.
3. Mainnet nodes used by honest participants work correctly.
4. No significant changes of the participant set are performed at once. Only one participant set change may be affected by a mainnet reorganization at the same time. 


### Multiparty protocols

Are required to achieve the "implementation secure enough to provide feeds to $1B+ TVL projects" objective.

1. **Deterministic feeds**. Attach to each privileged transaction at least M out of N (v, r, s)-signatures instead of `owner`'s signature.
    * **cons**:
        - only "manual" punishment (expulsion) for dishonest nodes
        - signees have to compute feeds in a deterministic way, even slightest disagreement ruins liveness.
        - dishonest nodes may skip the quoting work by copying other's results
        - up to `3340 * N` extra gas cost
        - small changes to the main contract
        - small coordination helper contract for a cheap net
        - small daemon changes

2. **almost deterministic feeds**. In the case when there is a disagreement on the feed data, extra stage is taken to sign the feed data where for each asset the price reported by at least M participants is taken, or the current one, if no such price exists.
    * **cons**:
        - only "manual" punishment (expulsion) for dishonest nodes
        - signees are urged to compute feeds in a deterministic way, but slight disagreements are acceptable.
        - dishonest nodes may skip the quoting work by copying other's results
        - up to `3340 * N` extra gas cost
        - extra stage in a case of a disagreement
        - small changes to the main contract
        - medium-complexity coordination helper contract for a cheap net
        - medium-complexity daemon changes

3. **Non-deterministic feeds, commit-reveal**. The first stage: commit of hashes of feed data. The second stage: feed data reveal. After the second stage, a median is computed for each asset in the cheap net's helper contract. During the third stage, an array of resulting medians is signed by all honest participants.
    * **cons**:
        - only "manual" punishment (expulsion) for dishonest nodes
        - up to `3340 * N` extra gas cost
        - extra 2 stages
        - small changes to the main contract
        - medium-complexity coordination helper contract for a cheap net
        - medium-complexity daemon changes

4. **Non-deterministic feeds, median-in-the-mainnet**. For feed update transactions signees also provide feed data along with signatures. In the main contract a median of the submitted values is computed. Commit-reveal makes no sense here since a byzantine node still can send his data to the main contract.
    * **cons**:
        - only "manual" punishment (expulsion) for dishonest nodes
        - dishonest nodes may skip the quoting work by copying other's results
        - up to `(3340 + calldata) * N` extra gas cost (up to `7000 * N` for 170 assets)
        - small changes to the main contract
        - small coordination helper contract for a cheap net
        - medium-complexity daemon changes

The last stage in the options 1-3 (M+ individual signings) may be replaced with a threshold ECDSA signature generation, eliminating the "up to `3340 * N` extra gas cost" downside, but adding complexity to the daemon. Additionally, any multi-signature participant change requires new group key generation and updating the owner of the main contract.

## Participants

The oracle is managed by a set of participating parties designated by an Ethereum-compatible key pair. There is a quorum requirement (a positive number not greater than the number of the participants) to enact an oracle operation.
There may be at least two approaches to cryptographically secure authorize an operation by such a participants committee:

* Transmit a quorum of signatures to the mainnet and verify them on-chain using `ecrecover` in a loop. Implementation of this approach is named the multisignature case in the document below. It's a simple solution but requires an extra approx. `5300 * (quorum - 1)` gas (further optimizations are possible).
* Create an Ethereum-compatible threshold signature and verify it on-chain using `ecrecover`. Signing the mainnet transaction itself is less favorable as changing the fee or the sender (see mainnet transacting schedule) requires re-signing. Implementation of this approach is named the threshold signature case in the document below.

Regardless of the way chosen, most of the protocol stays the same. Differences are highlighted.


## Message hashing & signing

The word "message" below in the phrases like "a hash of a message" or "a signature of a message" means a serialized typed structured data in accordance with EIP-712.
`keccak256` of such a message (which must also be used during signing) must be produced according to the standard. The message will be described with a `typeHash`.

`DOMAIN_SEPARATOR` must be computed as follows:

```solidity
DOMAIN_SEPARATOR = keccak256(
    abi.encode(
        keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak256(bytes("Metadata.Multiparty.Protocol")),
        keccak256(bytes("1")),
        chainid,
        oracleContractAddress
));
```

Where `chainid` is a chain id of the mainnet contract and `oracleContractAddress` is the mainnet contract address. The phrase "create calldata" below means to create transaction data for a mentioned function signature and arguments.


## Updating the oracle

### Epoch schedule

Epoch number (== epoch start time) for unix time `t` is `t / EPOCH_DURATION * EPOCH_DURATION`.
An epoch is divided into stages. Stage times below are unitless fractions and must be multiplied by `EPOCH_DURATION` to get the time in seconds since the start of the epoch.
Participant must process an epoch only once.


### Commit stage

The stage time range is [0, 0.15).

#### Participant

Detect prices for all known assets in any way feasible. If for an asset the price can't be determined, use NO_PRICE (== max uint) as a special value. Create a uint prices array ordered the order of the assets. Compute the hash of the message `Commit(address sender,uint32 epochId,uint256[] prices)` where `sender` is the participant's address. Transact `commit(epochId, hash)` to the contract.

#### The contract

`commit(uint32 epochId,  bytes32 hash)`. Check that `epochId` is current; the participant is valid; the participant has not yet transacted `commit` for the `epochId`. Record `epochId => participant => hash` & emit an event.


### Reveal stage

The stage time range is [0.15, 0.20). If a quorum of the committed hashes is not present, the epoch is marked as failed (but no explicit storage write is needed), no further actions are needed.

#### Participant

Transact `reveal(epochId,  prices, pricesSignature)` to the contract, where `prices` are the data created during the commit stage for the `epochId`.
`pricesSignature` is a signature of the message `Reveal(uint32 epochId,uint256[] prices)`.

*<small>Comment: `pricesSignature` is needed not to trust the side network and not to assume correct functioning of the used side network node.</small>*

#### The contract

`reveal(uint32 epochId, uint256[] prices, Signature pricesSignature)`. Check that `epochId` is current; the participant is valid; the participant has not yet transacted `reveal` for the `epochId`; the previously committed prices hash matches the hash of the `Commit` message constructed from `msg.sender`, `epochId`, `prices`.
Emit `epochId` in an event.

*<small>Comment: no need to record all the prices to the state or emit them as they can be read by participants from the tx data.</small>*


### Computation stage

If a quorum of the revealed price arrays is not present, the epoch is marked as failed (but no explicit storage write is needed), no further actions are needed.

#### Participant

Any participant which successfully revealed during the current epoch does the following.

Read successfully revealed prices from the corresponding transaction data. Take the participant set, quorum, current base prices, and epoch number from the mainnet contract. If the participant is not in the participant set, it stops the current epoch processing. Remove revealed prices reported by the participants not found on the mainnet or with incorrect `pricesSignature`. Remove duplicate submissions by the same participant. Compute the price for each asset: if no quorum is present (too many NO_PRICE or some were removed) then no price update (delta=0), the median of the prices otherwise (computed in Solidity uint terms).

*<small>Comment: filtering revealed prices is an extra safety check. Normally, nothing should be removed, see Participant set synchronization.</small>*

Translate resulting prices into full_update_assets, full_update_prices, new_delta_bytes arrays as in [updater.py](https://github.com/unitprotocol/neworacles/blob/7059f26f50f3798059254d28ed3c42d53c63d6a3/python/unitprotocol/fo/updater.py#L63-L111).

Sign the message `Update(uint32 epochId,uint32 previousEpochId,address[] assets,uint256[] basePrices,bytes deltas)` (where `previousEpochId` is the current epoch number, `assets` are full_update_assets, `basePrices` are full_update_prices, `deltas` are new_delta_bytes).

*<small>Comment: `previousEpochId` is needed because deltas are relative, and an update is applicable only to the state for which it was created.</small>*

* Multisignature case: transact `signed(epochId,  signature)` to the contract.
* Threshold signature case: TBD

#### The contract

* Multisignature case: `signed(uint32 epochId, signature)`: emit `epochId, signature` for a valid participant if not emitted yet and `epochId` is current.
* Threshold signature case: TBD

### Update stage

#### Participant

Gather a quorum of unique valid signatures or a threshold signature from the contract for the `Update` message produced at the previous stage. Use the participant set from the previous stage to check the validity of the signature participants. Transact to the mainnet contract along with the signature(s).


## Privileged functions

### Participant

Create calldata for a privileged transaction, e.g.: `addAsset(asset, currentPrice, salt, deadline)`.
* Multisignature case: sign the message `Vote(bytes calldata)` and transact `vote(calldata, signature)` to the contract. As soon as the quorum of unique valid signatures is present (from the current mainnet contract viewpoint), transact to the mainnet.
* Threshold signature case: sign the message `Vote(bytes calldata)`.

Note that each particular transaction calldata must include a unique salt to prevent replay attacks. Additionally, a deadline timestamp may be included to limit the    TTL of the action proposed.
Also, note that the privileged call signatures gathering requires scanning the entire side network contract lifetime for corresponding events.

### The side network contract

* Multisignature case: `vote(bytes calldata, signature)`: emit an event for a valid participant.
* Threshold signature case: TBD

### The main network contract

Check the signatures. Check the deadline, if any. Check that the given salt is not used yet; mark the salt as used. Exec the call (via self-call, perhaps).


## Participant set synchronization

Participant set synchronization (between the contracts) is desirable for participants filtering, but not required. Is done as a privileged function (see above), but with extra work performed.

*<small>Comment: the on-chain participant set management code may be shared between the contracts.</small>*

### Participant

Participants produce a privileged function signature(s). Participants don't initiate a new privileged function call on the side network until the current fully signed call is mined on the mainnet. Participants don't bypass the side network contract.

### The side network contract

* Multisignature case: detecting set modification calls (`addParticipant`, `setQuorum`, etc) via selectors, applying them to self (via self-call, perhaps), and emitting an event when the quorum is present.
* Threshold signature case: the current owner signs `NewOwner(address newOwner,uint quorum,address[] participants,uint salt,uint deadline)`, the contract extracts participants.


## Mainnet transacting schedule

Even when all participants are honest, there is the tragedy of the commons (of some degree) regarding paying for mainnet transactions. A simple schedule may be suggested to address the issue.

Let `T` be the time associated with some data, deterministic for all participants (e.g. `epochId` or the timestamp of the block when a quorum for the data was reached). Let `D` be an arbitrary mainnet-related duration, e.g. 1 minute for the Ethereum mainnet.

Then, `i`-th participant must deliver a transaction to the mainnet during the time slot starting at `T + D * (uint(keccak256(data)) + i) % totalParticipants` of the length `D`. The absence of such a transaction can be easily proven by looking at the mainnet.


### Updating the oracle

* The protocol does not rely on strict participant clock synchronization - in the worst case signed data won't match and multiparty signature won't be produced.
* Moreover, it's desirable to wait for some blocks after a stage beginning to avoid network reorganizations.
* The protocol relies on off-chain computations by the participants and doesn't rely on on-chain computation. Again, no multiparty signature in the worst case. Such an approach has several benefits: small gas footprint (heavy computations are impossible even on side networks), simpler code, no side network state dependence.


### Participant set synchronization

As an ultimate (and quite cheap) mitigation of the de-synchronization case, a new side network contract deployment may be suggested.

## Connectors

### DEXs connectors:

* UniswapV2Feed - for quoting assets at UniswapV2Like swaps: univ2, sushi, shiba, pancake
* UniswapV2LPFeed - for quoting liquidity pool tokens at UniswapV2Like swaps: univ2, sushi, shiba, pancake
* UniswapV3Feed - for quoting assets at UniswapV3 swap
* BearingFeed - for quoting bearing tokens.
* CurveLPFeed - for quoting liquidity pool tokens at curve.finance pools
* CurveFeed - for quoting assets at curve.finance pools
* YvFeed - for quoting yv tokens
* CompoundFeed - for quoting compound tokens

### CEXs connectors:

* SimpleStockFeed - quote of stocks
* BinanceFeed - for quoting assets at binance
* HuobiFeed - huobi
* KrakenFeed - kraken
* GateioFeed - gateio
* CoinbaseSimpleFeed - returns symbol price

### Other feeds:

* MulFeed - multiply price of one feed to another
* MedianFeed - find median value from multiple feeds prices, allowed to set count of absent values
* InvertFeed - 1 / feed price
* AliasFeed - add synonym to feed name
* ConstantFeed - for int constants
* FallbackFeed - Queries a list of feeds and returns the first successful response


### Multidata MedianFeeds: A Cost-Effective Alternative for Managing Metric Data on Blockchain Networks

Multidata MedianFeeds presents an innovative alternative approach to directly writing data on the target network, where transactional gas costs can be prohibitively expensive. By employing a multi-data chain with free gas and fallback to a cheaper network, MedianFeeds effectively minimizes costs while maintaining efficiency. This system uses tiny epochs, direct transactions from validators, and multiparty updates for metric and validator sets. Through a robust validation process involving Merkle tree roots, proofs, and metric value checks, MedianFeeds ensures data integrity and security. The accompanying JavaScript SDK also allows seamless integration with decentralized applications (DApps), making it a versatile and cost-effective solution for managing large-scale metric data.

### High-Level Overview

MedianFeeds:

* Tiny epoch (5 min) within a multidata chain with fallback to a cheaper network
* Direct transactions from each validator
* Not multiparty, since synchronization requires time
* Multiparty update for metric set and validator set
* Calculates median for each metric

Validators:

* Collect values for a large number of metrics
* Write all of them to MedianFeeds
* At the end of each round, retrieve values of all metrics on the block at the end of the epoch
* Create a Merkle tree and obtain the root
* Sign the Merkle tree root for each target network through a multiparty mechanism
* Send the root and VRS to MedianFeeds

Proof Feeds:

* Accept root, VRS, proof, metric value, timestamp, and epoch
* Verify that the root signature is correct
* Validate that the Merkle proof is valid for the root

JavaScript SDK:

* Allows DApps to retrieve metric values from MedianFeeds
* Collects values of all metrics on the block at the end of the last epoch
* Generates a Merkle tree, root, and proof for the required metric

Metric Values Users:

* Obtain epoch, Merkle root, VRS, Merkle proof, metric ID, metric value, and metric update timestamp from the JavaScript SDK
* Send this data to their own contract
* The contract checks if the metric update timestamp is suitable for its purposes
* The contract calls MerkleFeeds and verifies that the metric value and metric update timestamp are correct


#### MedianFeeds

Standard `ICoreMetadataOracleReader` interface for reading.

Due to implementation limitations, the price 2**256-1 is not supported.

Update values function: `update(uint32 epoch_, uint[] calldata metricIds_, uint256[] calldata prices_)`

Set signed Merkle tree root for the previous epoch for each target network:

```solidity
function setSignedMerkleTreeRoot(
    uint chainId_, address contractAddr_, uint32 epoch_, bytes32 root_,
    uint8 v_, bytes32 r_, bytes32 s_
);
```

Administrative functions (adding validators, adding/updating metrics) are the same as in the Multiparty oracle.

This function can be called several times per epoch by each validator, but with different metric IDs. It's recommended to send batches of 100 values. In this case, the gas cost will usually range between 1,138,512 and 9,262,586 (best to worst-case, depending on which metrics the median is calculated for).

#### Validators

The update of the metric and validator sets is the same as in MultiPartyFeeds.

It is necessary to port the following to Python (or find an existing implementation): https://github.com/OpenZeppelin/merkle-tree.

Each epoch, every validator sends all available values to MedianFeeds.

At the end of each MedianFeeds epoch (on the block of epoch end):

* Retrieve quotes for all metrics
* Calculate Merkle tree root for all values (epoch, metric ID, metric values, update timestamp ("uint32", "uint256", "uint256", "uint32")). See https://github.com/OpenZeppelin/merkle-tree
* Sign Merkle tree root for each contract in target networks and send to MedianFeeds (setSignedMerkleTreeRoot)

It might be necessary to allow sending roots not only from the previous epoch





## Main concepts
The connection of Multidata oracle to your smartcontract is quite easy. The examples below show how to get prices of `WETH` and `UNI-V2 WETH-CRV` and on Gnosis chain. 

### Proxies

Development of contracts is continuing and a new version of the oracle contract could be deployed. To avoid changing the oracle contract address on each such deployment consumers can use the address of the proxy contract, which has the same interface (`ICoreMetadataOracleReader`) as the oracle contract.

After the deployment of a new version of the oracle contract (and if the new version is backward compatible) implementation of the proxy is changed and migration for proxy users is seamless.

### Base 2**112 for prices

All prices are stored with base 2**112. It allows to sure values less than zero.
- 0.01 is stored as 0.01 * 2**112 = 51922968585348276285304963292200
- 100 is stored as 100 * 2**112 = 519229685853482762853049632922009600

## Examples on popular languages (multiparty feed)
### Solidity

To use oracle's prices in your smartcontract interface `ILegacyMetadataOracleV0_1` should be used.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/legacy/ILegacyMetadataOracleV0_1.sol";

contract DataConsumerLegacy {
    
    ILegacyMetadataOracleV0_1 internal oracle;

    /**
     * network: Gnosis
     * oracle address: 0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA
     */
    constructor() {
        oracle = ILegacyMetadataOracleV0_1(0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA);
    }

    /**
     * Returns prices of `ETH` and `UNI-V2 WETH-CRV` in USD
     */
    function getLatestPrices() public view returns (uint[2] memory) {
        address[] memory assets = new address[](2);
        assets[0] = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        assets[1] = 0x3dA1313aE46132A397D90d95B1424A9A7e3e0fCE;

        ILegacyMetadataOracleV0_1.Quote[] memory values = oracle.quoteAssets(assets);

        return [
            values[0].price / 2**112,
            values[1].price / 2**112
        ];
    }
}
```

## JavaScript
### web3

This example uses [web3.js](https://web3js.readthedocs.io/) to fetch prices of `ETH` and `UNI-V2 WETH-CRV` in Gnosis chain.

```js
    const Web3 = require("web3")
    const ORACLE_ADDR = '0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA';
    const RPC_URL = "https://rpc.gnosischain.com";
    const ASSETS = [
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        '0x3dA1313aE46132A397D90d95B1424A9A7e3e0fCE',
    ]
    const oracleReaderABI = [{"inputs": [{"internalType": "address[]","name": "assets","type": "address[]"}],"name": "quoteAssets","outputs": [{"components": [{"internalType": "uint256","name": "price","type": "uint256"},{"internalType": "uint32","name": "updateTS","type": "uint32"}],"internalType": "struct ILegacyMetadataOracleV0_1.Quote[]","name": "quotes","type": "tuple[]"}],"stateMutability": "view","type": "function"}]

    const web3 = new Web3(RPC_URL)
    const oracle = new web3.eth.Contract(oracleReaderABI, ORACLE_ADDR)
    oracle.methods.quoteAssets(ASSETS)
        .call()
        .then((prices) => {
            // handle code
            console.log("Latest prices", prices)
        })
```

### ethers.js

This example uses [ethers.js](https://docs.ethers.io/) to fetch prices of `ETH` and `UNI-V2 WETH-CRV` in Gnosis chain.

```js
    const { ethers } = require("ethers")
    const ORACLE_ADDR = '0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA';
    const RPC_URL = "https://rpc.gnosischain.com";
    const ASSETS = [
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        '0x3dA1313aE46132A397D90d95B1424A9A7e3e0fCE',
    ]
    const oracleReaderABI = [{"inputs": [{"internalType": "address[]","name": "assets","type": "address[]"}],"name": "quoteAssets","outputs": [{"components": [{"internalType": "uint256","name": "price","type": "uint256"},{"internalType": "uint32","name": "updateTS","type": "uint32"}],"internalType": "struct ILegacyMetadataOracleV0_1.Quote[]","name": "quotes","type": "tuple[]"}],"stateMutability": "view","type": "function"}]

    const provider = new ethers.providers.JsonRpcProvider(RPC_URL)
    const oracle  = new ethers.Contract(ORACLE_ADDR, oracleReaderABI, provider)
    oracle.quoteAssets(ASSETS)
        .then((prices) => {
            // handle code
            console.log("Latest prices", prices)
        })
```

## Python

This example uses [web3.py](https://web3py.readthedocs.io/) to fetch prices of `ETH` and `UNI-V2 WETH-CRV` in Gnosis chain.

```python
from web3 import Web3

ORACLE_ADDR = '0xf315a5cc91338a3886d3c3a11E7b494f3302B3fA'
RPC_URL = "https://rpc.gnosischain.com"
ASSETS = [
    '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    '0x3dA1313aE46132A397D90d95B1424A9A7e3e0fCE',
]
ORACLE_READER_ABI = [{"inputs": [{"internalType": "address[]","name": "assets","type": "address[]"}],"name": "quoteAssets","outputs": [{"components": [{"internalType": "uint256","name": "price","type": "uint256"},{"internalType": "uint32","name": "updateTS","type": "uint32"}],"internalType": "struct ILegacyMetadataOracleV0_1.Quote[]","name": "quotes","type": "tuple[]"}],"stateMutability": "view","type": "function"}]


web3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = web3.eth.contract(address=ORACLE_ADDR, abi=ORACLE_READER_ABI)
latestPrices = contract.functions.quoteAssets(ASSETS).call()
print(latestPrices)
```

# For Chainlink users

We provide Chainlink-compatible aggregator (`IChainlinkAggregatorV2V3Interface`) for every quoted asset which allows to get the latest price of asset. 

See below example of getting prices for `ETH` and `UNI-V2 WETH-CRV` with chainlink compatible aggregators in Gnosis chain

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IChainlinkAggregatorV2V3Interface.sol";

contract DataConsumerChainlinkCompatibility {
    
    IChainlinkAggregatorV2V3Interface internal aggregatorEth;
    IChainlinkAggregatorV2V3Interface internal aggregatorLpWethCrv;

    /**
     * network: Gnosis
     */
    constructor() {
        aggregatorEth = IChainlinkAggregatorV2V3Interface(0x05B10FAd302f202809BF2Fd1F1456e211C1A9B20);
        aggregatorLpWethCrv = IChainlinkAggregatorV2V3Interface(0xD3DCD5fEB3ffB266C6d9829607271dEa61eBa84C);
    }

    /**
     * Returns prices of `ETH` and `UNI-V2 WETH-CRV` in USD
     */
    function getLatestPrices() public view returns (uint[2] memory) {
        (,int priceEth,,,) = aggregatorEth.latestRoundData();
        (,int priceLP,,,) = aggregatorLpWethCrv.latestRoundData();

        return [
            uint(priceEth) / 10**8,
            uint(priceLP) / 10**8
        ];
    }
}
```

# Oracle Api reference

## ILegacyMetadataOracleV0_1

Functions in `ILegacyMetadataOracleV0_1`

| Name                                     | Description                                  | Returns                                       |
|------------------------------------------|----------------------------------------------|-----------------------------------------------|
| `getStatus`                              | Returns last update TS of prices             | `Status {uint32 updateTS;uint64 pricesHash;}` |
| `getAssets`                              | Gets a list of assets quoted by this oracle. | `address[]`                                   | 
| `hasAsset(address asset)`                | Checks if an asset is quoted by this oracle. | `bool`                                        |
| `quoteAssets(address[] calldata assets)` | Gets last known quotes for the assets        | `Quote[] {uint256 price;uint32 updateTS;}`    |



# Examples of usage by DEFI projects


Let's describe line-by-line how it works:

```solidity
...
interface IOracleUsd {
    function assetToUsd(address asset, uint256 amount) external view returns (uint256);
}

/// @title MetadataOracle wrapper for Unit protocol
contract UnitMetadataOracle is IOracleUsd {
    // Multidata oracle's address is stored in immutable. It allows to save gas on read of this variable
    ICoreMetadataOracleReader public immutable metadataOracle;
    // Also immutable variable, stores max allowed price age
    uint256 public immutable maxPriceAgeSeconds;

    constructor(address metadataOracle_, uint256 maxPriceAgeSeconds_) {
        metadataOracle = ICoreMetadataOracleReader(metadataOracle_);
        maxPriceAgeSeconds = maxPriceAgeSeconds_;
    }

    /**
     * @notice Evaluates the cost of amount of asset in USD.
     * @dev reverts on non-supported asset or stale price.
     * @param asset evaluated asset
     * @param amount amount of asset in the smallest units
     * @return result USD value, scaled by 10**18 * 2**112
     */
    function assetToUsd(address asset, uint256 amount) external view override returns (uint256 result) {
        // Prepare arguments for calling oracle. Despite the dact that we need to quote only one price
        // we still need to make array
        address[] memory input = new address[](1);
        input[0] = asset;
        // quoteAssets returns array. Since we pass only one asset in argument only one element is returned.
        ICoreMetadataOracleReader.Quote memory quote = metadataOracle.quoteAssets(input)[0];
        // Here we see very important concept of using oracles: we need to check that price returned by oracle
        // is up to date. Usage of outdated price may lead to losses
        require(block.timestamp - quote.updateTS <= maxPriceAgeSeconds, 'STALE_PRICE');

        // Multidata oracle store price for whole unit of currency (taking in account 2**112 base)
        // For example price for 1 eth is stored as X * 2**112 USD where X is the price in USD
        // Unit protocol wants to get price for amount of asset passed in min units of asset in USD with decimals 18
        // For example to get price for 1 WETH unit protocol passes 10**18 as amount 
        // and wants to get X * 10**18 * 2**112 in response where X is the price in USD
        // If asset has decimal <> 18 price must be scaled accordingly
        uint256 decimals = uint256(IERC20Like(asset).decimals());
        require(decimals < 256);
        // Let's assume that we need to get price for 1 USDT which has decimals = 6.
        // 10**6 is passed as amount
        // scaleDecimals = 18-6=12
        int256 scaleDecimals = 18 - int256(decimals);

        // result = 1 * 2**112 * 10**6
        result = quote.price * amount;
        if (scaleDecimals > 0)
        // result = 1 * 2**112 * 10**6 * 10**12 = 1 * 2**112 * 10**18. So price 1 with base 2**112 and decimals 18 is returned
            result *= uint256(10) ** uint256(scaleDecimals);
        else if (scaleDecimals < 0)
            result /= uint256(10) ** uint256(-scaleDecimals);
    }
}
```

## Simple stable with Multidata oracle example

As an example of integration BubHub oracle to DEFI projects let's create simple stablecoin backed with several assets.

### Requirements

For our example we formulate just a few requirements. Please see section [What next?](#what-next) additionally

- Issue stablecoin backed with any asset for which oracle has price
- Repay debt


### Developing of the contract

First will create skeleton of our stable. We will inherit from OpenZeppelin ERC20 contract and will pass oracle's address as constructor argument.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../interfaces/legacy/ILegacyMetadataOracleV0_1.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SimpleStable is ERC20 {
    
    ILegacyMetadataOracleV0_1 internal oracle;

    constructor(ILegacyMetadataOracleV0_1 oracle_) ERC20('Stablecoin', 'STBL') {
        oracle = oracle_;
    }

}
```

Then will add structures to store information about issued stables and stored collaterals for user. And also will add skeletons of methods for borrow and repay debt. To execute `borrow` method user must approve `assetAmount_` of `asset_` to our contract.

```solidity
...
    /**
     * @notice user => asset => debt
     */
    mapping (address => mapping (address => uint)) public debts;
    mapping (address => mapping (address => uint)) public collaterals;
...
    function borrow(address asset_, uint assetAmount_) public {
    }

    function repay(address asset_) public {
    }
...
```

Next will add `nonReentrant` modificator for our methods to prevent malicious actions from assets (they could try to call methods of stable coin inside of `asset`.`transfer` method)

```solidity
...
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SimpleStable is ERC20, ReentrancyGuard {
...

    function borrow(address asset_, uint assetAmount_) public nonReentrant {
...

    function repay(address asset_) public nonReentrant {
...
```

Then let's add method for retrieving price of asset. Method makes request to Multidata oracle network, checks that price is up-to-date and returns price.

```solidity
...
    uint public constant MAX_PRICE_AGE = 3 hours;
...
    function getPriceBase112(address asset_) internal view returns (uint) {
        address[] memory assets = new address[](1);
        assets[0] = asset_;

        ILegacyMetadataOracleV0_1.Quote[] memory values = oracle.quoteAssets(assets);
        require(block.timestamp - values[0].updateTS <= MAX_PRICE_AGE, 'STALE_PRICE');

        return values[0].price;
    }
...
```

Next will implement borrow method. This method gets collateral from user and issue stables to this user.

```solidity
...
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
...
contract SimpleStable is ERC20, ReentrancyGuard {
    using SafeERC20 for IERC20;
...
    function borrow(address asset_, uint assetAmount_) public nonReentrant {
        // we can get as collateral only assets for which we know price 
        require(oracle.hasAsset(asset_), "Asset is not supported");
        // to simplify example we allow borrow only once per asset
        require(debts[msg.sender][asset_] == 0, "Debt already exists");

        // calculation of total debt:
        // debt = price * amount * 10**(decimals of stable) / 10**(decimals of asset) / 2**112
        // lets look deeply to components of this formula
        // - price - price in oracles is store with multiplied to 2**112 and stored for 1 unit of asset.
        // - amount - we want to know price of all collateral
        // - 10**(decimals of stable) / 10**(decimals of asset) = 10**(18-assetDecimals) - adjusting with decimals of asset and our stable coin (=18)
        // - 2**112 - divide to price base
        uint assetDecimals = IERC20Metadata(asset_).decimals();
        uint debt = getPriceBase112(asset_) * assetAmount_ * 10**(18-assetDecimals) / 2**112;

        // save information about debt and stored collateral
        debts[msg.sender][asset_] = debt;
        collaterals[msg.sender][asset_] = assetAmount_;

        // mint stablecoin right to user
        _mint(msg.sender, debt);
        // get collateral from user. We use safeTransfer to fail on any error during transfer
        IERC20(asset_).safeTransferFrom(msg.sender, address(this), assetAmount_);
    }
...
```

And the last method for repay debt

```solidity
...
    function repay(address asset_) public nonReentrant {
        // execute only for borrowers
        uint debt = debts[msg.sender][asset_];
        require(debt > 0, "No debt");

        // collateral of borrower
        uint collateralAmount = collaterals[msg.sender][asset_];

        // clear info about debt and collaterals
        debts[msg.sender][asset_] = 0;
        collaterals[msg.sender][asset_] = 0;

        // burn stablecoin right from user's account. No need to approve stablecoin
        _burn(msg.sender, debt);
        // transfer collateral to user. Fail on eny error
        IERC20(asset_).safeTransfer(msg.sender, collateralAmount);
    }
...
```

That's all :) Full code of contract you can see on [SimpleStable.sol](/contracts/defi/SimpleStable.sol).

Also you can see simple test for this contract [here](/test/defi/SimpleStableTest.js). In this test [Mock of oracle](/contracts/test-helpers/OracleMock.sol) was used.



### Collateralization ratio
We issue stablecoin for full values of collateral. It is wrong since after some small price dump we will have value of issued stables < values of collaterals. It will lead to depeg of stable coin. 

To avoid this such parameter as `Initial collateralization ratio (ICR)` must be introduced. `ICR` = `Issued stablecoins` / `Current value of colateral`. For example with CR = 70% with collateral with value $100 only 70 stablecoin could be issued.

Going further since different assets have different volatility `ICR` must be different for different assets. For more volatile assets (for example which price can change for 100%/day) CR must be small. For more stable assets CR could be bigger.

### Changes in position

To simplify example we allow issuing stablecoints only once for each asset and repay only whole debt. It is convenient for user to increase/decrease their position. `ICR` of total debt and total value of collateral must be taken in account in such cases.

### Liquidations

What happens if price dump is much more than `Collateralization ratio` could compensate? We will have unbacked debt again. To avoid such situtions liquidation mechanism and `Liquidation ratio` must be introduced.

If current `CR` is more `ICR` for some value (`Liquidation ratio`) auction to sell debt of user must be started. After debt is bought in auction, buyer receives part of collateral (values as repaid stables + some premium), the rest of collateral goes to initial borrower.


## Multidata Network Roadmap
1. Factory of user-defined oracles
1. API for historical data
   * as an additional exporter
   * daily logs - to a S3 bucket
3. Liquidity control.
    * `Uniswap*Feed` : don't produce a quote if the pool is illiquid.
    * the same for `Curve*`
    * control for CEXes?
4. Multi-party. 
5. More tests for feeds.
6. Use type `2` Ethereum transactions on Ethereum mainnet.
7. Contracts v2.
     * externally set epoch timestamps (plus: for replay attack protection). Done in multiparty.
     * `setPrices+updateDeltas` combined function. Done in multiparty.
     * `epoch+baseprices+assets+...`  combined getter. Done in multiparty.
     * increase the compiler runs parameter, but check the effects on gas and contract sizes
     * can `AggregatorShim` be replaced with lightweight proxies a la in Wrapped SSLP?
     * individual update timestamps for assets
     * doc-comments
9. Computations.
    * use `Decimal` everywhere
    * remove any `float` intermediaries
10. Split the `neworacles` monolith into a set of reusable libraries (packages) and services (in dedicated repos)
11. Multi-tiered liquidity-price results, e.g.: `[($100_000, $0.5), ($1000_000, $0.4), ($10_000_000, $0.2)]`.
12. Don't require intermediate feed naming in config.
    * e.g., write Mul(UniswapFeed(...), ETHUSD) without a name for UniswapFeed.
13. Automatic feed detection & configuration. For fucking everything.
14. Super integration tests (?Smoke-tests) 
    * on push to master run instance with the same oracles config as in production
    * write prices to testnet
    * check that prices were written and maybe compare them to cmc
14. More data feeds
    * Currencies
    * Commodities
    * Bonds

### Undisputed objectives

1. Implementation secure enough to provide feeds to $1B+ TVL projects.
2. Gas-efficient.
3. Each asset must have an update timestamp.


## Glossary

**Logarithmic delta encoding** is a technique that is used to minimize the amount of data that needs to be transmitted when updating a value, such as a price quote. It works by only transmitting the difference between the new value and the previous value, rather than the entire new value. This can be particularly useful when the values being transmitted are expected to change significantly over time, as it allows for more efficient updates by transmitting only the changes rather than the entire new value. Together with batched updates, this yields impressive network fee savings.

**Elliptic Curve Digital Signature Algorithm (ECDSA)** is a cryptographic algorithm that is used to create digital signatures. It is a variant of the Digital Signature Algorithm (DSA) and is based on the mathematics of elliptic curves.

Digital signatures are used to verify the authenticity and integrity of a message or piece of data. They work by generating a unique, unforgeable signature for the data using a private key, which can then be verified using a corresponding public key. This allows the recipient of the signed data to verify that it has not been tampered with and that it was indeed sent by the owner of the private key.

ECDSA is widely used in various applications, including blockchain technology, where it is often used to create digital signatures for transactions. It is considered to be more secure and efficient than some other digital signature algorithms, and is used in many cryptographic protocols, including SSL/TLS, PGP, and SSH.

**EIP-712** is an Ethereum Improvement Proposal that outlines a standard for creating structured messages in the Ethereum ecosystem. Structured messages are data structures that can be signed and verified by Ethereum wallets and smart contracts, and they can be used to communicate complex data between parties in a secure and verifiable way. EIP-712 defines a standard format for structured messages, including the fields that must be included and the encoding rules that must be followed. It also specifies the use of domain separation, which allows multiple structured messages to coexist within the same Ethereum ecosystem without conflicting with each other. EIP-712 was created to improve the usability and security of communication in Ethereum.

**keccak256** is a cryptographic hash function that is used to create a fixed-size, unique hash value (also called a message digest) from an input message. It is part of the SHA-3 (Secure Hash Algorithm 3) family of hash functions, which were designed to be secure and resistant to attack. keccak256 is commonly used in Ethereum to create a unique identifier for a contract or other data on the blockchain. The hash value is computed by applying the keccak256 algorithm to the input message, and it is typically represented as a string of 64 hexadecimal characters. Because the hash value is fixed-size and unique, it can be used to verify the integrity and authenticity of the input message, as well as to detect any changes to the message.

**Multi-tiered liquidity-price** results are one of the important tools in financial markets for determining the relationship between liquidity and price for a particular asset. In simple terms, liquidity refers to the amount of an asset that is available for trade, while price refers to the cost of purchasing the asset. Understanding the relationship between these two factors is crucial for traders and investors, as it allows them to make informed decisions about when and how to buy or sell an asset.

One way to represent this relationship is through the use of multi-tiered liquidity-price results. These results are essentially lists of liquidity-price pairs that are sorted in order of increasing liquidity. Each pair indicates the liquidity and price associated with a particular trade size. For example, a liquidity-price pair may indicate that a liquidity of $100,000 is associated with a price of $0.5, while another pair may indicate that a liquidity of $1,000,000 is associated with a price of $0.4.

Multi-tiered liquidity-price results are often used by financial institutions, such as banks and brokers, to determine the optimal trade size and price for a particular asset. 

**A price-weighted index** is a type of stock market index that reflects the changes in the value of a group of stocks based on the price of each stock, rather than the market capitalization (the total value of all the shares of a company). The value of the index is calculated by taking the sum of the prices of all the stocks in the index, and dividing it by the total number of stocks in the index. The value of the index is then adjusted for any changes in the number of stocks in the index.

For example, suppose we have a price-weighted index that tracks the prices of three stocks: Stock A, Stock B, and Stock C. The prices of these stocks are $100, $50, and $200, respectively. The value of the index would be calculated as follows:

(100 + 50 + 200) / 3 = $116.67

If the price of Stock B were to increase to $75, the value of the index would be recalculated as follows:

(100 + 75 + 200) / 3 = $133.33

**Price-weighted indices** are typically used to track the performance of a group of stocks that have similar characteristics, such as stocks in a particular sector or industry. They are generally considered to be a simple and easy-to-understand way to track the performance of a group of stocks. However, they have some drawbacks compared to other types of stock market indices. For example, because the value of the index is determined by the prices of the individual stocks, it is more susceptible to changes in the prices of a few heavily weighted stocks, rather than the overall performance of the group as a whole. Additionally, price-weighted indices do not take into account the market capitalization of the stocks in the index, which can lead to a bias towards larger, more established companies.

**Capitalization-weighted index** is a type of financial index that measures the performance of a group of securities, such as stocks or bonds, in a market. The weight of each security in the index is determined by its market capitalization, which is calculated by multiplying the security's price by the number of outstanding shares. Securities with a higher market capitalization have a greater influence on the performance of the index.

For example, suppose an index includes three stocks: Stock A, Stock B, and Stock C. Stock A has a market capitalization of $100 million, Stock B has a market capitalization of $50 million, and Stock C has a market capitalization of $25 million. The weight of Stock A in the index would be 40%, the weight of Stock B would be 20%, and the weight of Stock C would be 10%. This means that the performance of Stock A would have a greater impact on the overall performance of the index compared to the performance of Stock B and Stock C.

Capitalization-weighted indexes are commonly used to track the performance of a particular market or sector. For example, the S&P 500 is a well-known capitalization-weighted index that tracks the performance of the 500 largest publicly traded companies in the United States. Other examples of capitalization-weighted indexes include the NASDAQ 100, which tracks the performance of the 100 largest non-financial companies listed on the NASDAQ stock exchange, and the FTSE 100, which tracks the performance of the 100 largest companies listed on the London Stock Exchange.

# Contacts
[Site](https://multidata.ai)
[Explorer](https://explorer.multidata.ai)
hello@multidata.ai
