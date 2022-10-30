# Orochimaru

Orochimaru is a full-node client of Orochi Network which was implemented pure in Rust programing language

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

## License

Licensed under [Apache License 2.0](./LICENSE)

_built with ❤️_
