# Orochimaru

Orochimaru is a full-node client of Orochi Network which was implemented pure in Rust programing language

## Installation

You must install `sea-orm-cli` first:

```
cargo install sea-orm-cli
```

Generate entity for sqlite:

```
sea-orm-cli generate entity -o ./src/sqlite
```

Migrate database or init database for the first time:

```
sea-orm-cli migrate
```

## Components

### Orand: Decentralized Random Number Generator

A Decentralized Random Number Generator by Orochi Network. Allowed randomness to be generated and fed to any smart contracts on EVM compatible blockchains.

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

- **Verifiable randomness:** We're using Elliptic Curve Verifiable Random Function (ECVRF) to generate randomness the process described here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-05#section-5.3. Curve secp256k1 and keccak256 (Ethereum variant) was used to minimizing verification cost for smart contract.

- **Dispersity:** A distributed system with many participants/nodes will join to generate randomness by using Multi Party Computation (MPC)

- **Unpredictability:** A VRF will perform with the input is previous randomness and it’s also require half of participants to participate in MPC

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

### Demo

```
~/GitHub/orochimaru/ecvrf $ cargo run
   Compiling secp v0.1.0 (/Users/chiro/GitHub/orochimaru/ecvrf)
    Finished dev [unoptimized + debuginfo] target(s) in 0.87s
     Running `target/debug/secp`
gamma:
 > x: 0xaee4a6b5fcfa1094a80bb73b4e02e5a5d236b71c4563abda50b999ac8a095be1
 > y: 0x149ed72cbdb6e7cad92c0ea0ed7d4512e2015ddf92482c3a75d325a4d4928b89
c: 0xcf6df09d8cb1b2262ecf3c5527eb089dfcbf616f34fb608701ca90be006b4368
s: 0xecbb41a7d6276dd3f8f52e61450a44dc9ac3b091462a3f47be69edb754635ae5
y: 0x93500089dc9512508b2fbc91b9f1e15526f76d59fed1f180b21878449fe47e21
public key:
 > x: fb8881e4cc8225ed54f7473ab9c6bab9e7152e58c79517b48434466d6ab056a4
 > y: 84ef2334b53ff8f499cb2134643984ef92e2ecec5635eb4c90adb8022f4d3ea7

Verified: true
```

## License

Orochi Network's source code licensed under [Apache License 2.0](./LICENSE)

_built with ❤️_
