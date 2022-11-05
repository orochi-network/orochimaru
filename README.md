# Orochimaru

[![Lines of code][line-of-code]][loc-url]

[line-of-code]: https://img.shields.io/tokei/lines/github/orochi-network/orochimaru
[loc-url]: https://img.shields.io/tokei/lines/github/orochi-network/orochimaru

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

#### Orand v1.0 is providing:

- **Verifiable randomness:** We're using Elliptic Curve Verifiable Random Function (ECVRF) to generate randomness the process described here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-05#section-5.3. Curve secp256k1 and keccak256 (Ethereum variant) was used to minimizing verification cost for smart contract.

- **Dispersity:** A distributed system with many participants/nodes will join to generate randomness by using Multi Party Computation (MPC)

- **Unpredictability:** A VRF will perform with the input is previous randomness and it’s also require half of participants to participate in MPC

- **High throughput:** Game server could request randomness from the Orand system. The result will be provided as soon as half of participants participate in the MPC.

- **Cheap and secure randomness:** For the free tier, randomnesses will be given freely for the first 20,000 randomnesses every month.

- **Fault Proof:** If the game server tries to delay the feeding process to manipulate the result, a fault proof will be committed so sue the game server.

- **Multi-chain:** All EVM compatible blockchains can be supported

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
