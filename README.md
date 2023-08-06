<p align="center">
    <img src="./assets/orochimaru.png" alter="Orochimaru desu?">
</p>

## Orochimaru

Orochimaru is a full-node client of Orochi Network which was implemented in pure Rust programming language. Orochi Network isn't a blockchain but a distributed network built to perform Multi Party Computation (MPC) and Zero-Knowledge Proof (ZKP) proving from which we provide trustless and Verifiable Computation. Our mission is to establish High Performance dApp.

## Orochi Network

At [Orochi Network](https://orochi.network), we believe that Verifiable Computation is a critical primitive to establish Web3 and Decentralized Autonomous Economy. However, in order to reach this stage, there are still a number of major challenges in this industry to overcome.

- **The limits of computation:** EVM can not guarantee semi-native performance, in addition to the extremely high cost and latency to perform computation. dApps nowadays are unfriendly to the mass, unstable, expensive and slow. In other words, they are currently unusable and we can not replace an ordinary application by a dApp yet.
- **Data correctness:** There is no way to prove the correctness of data since all data pipelines are stored in a blackbox. We have no idea how data are processed.
- **Data availability:** Smart contract executor and application executor are isolated from the internet that prevent data to be accessible from the run-time environment. It always requires a third party service to feed necessary data. This approach is broken since we can not verify the data. Moreover, the latency from the third parties is unacceptable.

```text
┌─────────────────────────────┐
│                             │
│ ┌─────────────────────────┐ │
│ │   Orosign - zkOS's UI   │ │
│ └─────────────────────────┘ │
│                             │
│ ┌─────────────────────────┐ │
│ │  High Performance dApp  │ │
│ └─────────────────────────┘ │
│                             │
│ ┌───────────┐ ┌───────────┐ │
│ │zkDatabase │ │   Orand   │ │
│ └───────────┘ └───────────┘ │
│                             │
│ ┌─────────────────────────┐ │
│ │          zkWasm         │ │
│ └─────────────────────────┘ │
│                             │
└─────────────────────────────┘

┌─────────────────────────────┐
│       Settlement Layer      │
└─────────────────────────────┘
```

Our solution is to build a universal run-time environment (zkWasm) that provides Verifiable Computation. We can build up the verifiable data pipeline on top of our zkWasm to solve the correctness and availability challenges of the data.

## Components

### Orand: Decentralized Random Number Generator

Allowed verifiable randomness to be generated and fed to any smart contracts on EVM compatible blockchains. Orand uses Elliptic Curve Verifiable Random Function (ECVRF) to prove and verify randomness. You can learn more about ECVRF in our blog [blog.orochi.network](https://blog.orochi.network).

#### Request randomness

```
┌───────────┐         ┌─────┐      ┌──────────────┐
│Application│         │Orand│      │Smart Contract│
└─────┬─────┘         └──┬──┘      └──────┬───────┘
      │                  │                │
      │Request Randomness│                │
      │─────────────────>│                │
      │                  │                │
      │                  │Get latest epoch│
      │                  │───────────────>│
      │                  │                │
      │                  │  Latest epoch  │
      │                  │<───────────────│
      │                  │                │
      │   ECVRF Proof    │                │
      │<─────────────────│                │
      │                  │                │
      │            ECVRF Proof            │
      │──────────────────────────────────>│
┌─────┴─────┐         ┌──┴──┐      ┌──────┴───────┐
│Application│         │Orand│      │Smart Contract│
└───────────┘         └─────┘      └──────────────┘

```

#### Orand v1.0 is providing:

- **Verifiable randomness:** We're using Elliptic Curve Verifiable Random Function (ECVRF) to generate randomness in the process described here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-05#section-5.3. Curve secp256k1 and keccak256 (Ethereum variant) was used to minimizing verification cost for smart contract.

- **Dispersity:** A distributed system with many participants/nodes will join to generate randomness by using Multi Party Computation (MPC)

- **Unpredictability:** A VRF will perform with the input is previous randomness and it also requires half of participants to participate in MPC

- **High throughput:** Game server could request randomness from the Orand system. The result will be provided as soon as half of participants participate in the MPC.

- **Cheap and secure randomness:** For the free tier, randomnesses will be given freely for the first 20,000 randomnesses every month.

- **Fault Proof:** If the game server tries to delay the feeding process to manipulate the result, a fault proof will be committed so sue the game server.

- **Multi-chain:** All EVM compatible blockchains can be supported

### API Testing

First starting the service with:

```txt
~ $ cargo run
```

Request service to generate an epoch for a given network:

```txt
curl -X POST --data '{"method":"orand_newEpoch","params":["56"]}' http://localhost:3000
```

Result:

```txt
{
    "id": 20,
    "network": 56,
    "keyring_id": 1,
    "epoch": 19,
    "alpha": "2979a78ca2e72317dacf8ac511b48486eeac234dbdcf68c82c787d4adb9a2b17",
    "gamma": "ce809816f05ae6be2c30a8ae9133a53e2095d4d65d15d009e3c5d6be39a83d8eca32382fd95549dd5d3f82d55c71b7d002e5518897d29f20b9ddefc8f137bf36",
    "c": "563103eac20acbec7ed2b2abb0327614f38f7bb2b51c12b049d4a184372bdae2",
    "s": "56af973100d38743a144dab6e70278f09dfa5aba96531ad271b99eb68c89e44e",
    "y": "db2ad98900d91b67a117fc388a20d193ea7152cc05c70479bd9b40beab51d2bd",
    "created_date": "2022-11-11 07:22:36"
}
```

List recent epoch

```txt
curl -X POST --data '{"method":"orand_getPublicEpoch","params":["56","15"]}' http://localhost:3000
```

Result:

```txt
[{
    "id": 16,
    "network": 56,
    "keyring_id": 1,
    "epoch": 15,
    "alpha": "3bc01ff25a742df287f7038063829a8822e91c3f31aeb75b13a6b6eb8950e31b",
    "gamma": "84b4d75c4c7f5d72e155c4b4652286e25f3ade2bbdf391adf9ca0e9e464c60cc2c181327795728913d1f6dd2b407cc61c8d30190455b3a626d8a969219f6e8c3",
    "c": "d7b9aca852b932ce253776402f8c607149366819140fd6d58cfbcfa3b93c9ce5",
    "s": "e34344e4a35f153fbd95b5b44f192160a8fa397a4008af6b4f6ac31ffcc60c80",
    "y": "7b639ee0ee5807b39f012a4f181374e17a36f94b8c35ec4dfc1962069fd8d426",
    "created_date": "2022-11-11 04:56:28"
},
//...
, {
    "id": 20,
    "network": 56,
    "keyring_id": 1,
    "epoch": 19,
    "alpha": "2979a78ca2e72317dacf8ac511b48486eeac234dbdcf68c82c787d4adb9a2b17",
    "gamma": "ce809816f05ae6be2c30a8ae9133a53e2095d4d65d15d009e3c5d6be39a83d8eca32382fd95549dd5d3f82d55c71b7d002e5518897d29f20b9ddefc8f137bf36",
    "c": "563103eac20acbec7ed2b2abb0327614f38f7bb2b51c12b049d4a184372bdae2",
    "s": "56af973100d38743a144dab6e70278f09dfa5aba96531ad271b99eb68c89e44e",
    "y": "db2ad98900d91b67a117fc388a20d193ea7152cc05c70479bd9b40beab51d2bd",
    "created_date": "2022-11-11 07:22:36"
}]
```

## Installation

You must install `sea-orm-cli` first:

```
cargo install sea-orm-cli
```

Generate entity for sqlite _(you don't need to perform this step)_:

```
sea-orm-cli generate entity -o ./entity
```

Migrate database or init database for the first time:

```
sea-orm-cli migrate
```

## License

Orochi Network's source code licensed under [Apache License 2.0](./LICENSE)

_built with ❤️_
