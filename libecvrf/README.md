# Libecvrf

A library from Orand @ [Orochi Network](https://orochi.network)

## Overview

In cryptography, a verifiable random function (VRF) is a public key version of a pseudorandom function. It produces a pseudorandom output and a proof certifying that the output is computed correctly.

A VRF includes a pair of keys, named public and secret keys. The secret key, along with the input is used by the holder to compute the value of a VRF and its proof, while the public key is used by anyone to verify the correctness of the computation.

The issue with traditional pseudorandom functions is that their output cannot be verified without the knowledge of the seed. Thus a malicious adversary can choose an output that benefits him and claim that it is the output of the function. VRF solves this by introducing a public key and a proof that can be verified publicly while the owner can keep secret key to produce numbers indistinguishable from randomly chosen ones.

VRF has applications in various aspects. Among them, in internet security, it is used to provide privacy against offline enumeration (e.g. dictionary attacks) on data stored in a hash-based data structure [irtf-vrf15](https://datatracker.ietf.org/doc/rfc9381/). VRF is also used in lottery systems [MR02](https://people.csail.mit.edu/rivest/pubs/MR02a.prepub.pdf) and E-cashes [BCKL09](https://eprint.iacr.org/2009/107).

## Features

This library is a part of Orand a Decentralized RNG (or Public Randomness Beacon). This crate provide two main features, ordinary ECVRF describe in [irtf-vrf15](https://datatracker.ietf.org/doc/rfc9381/) and EVM friendly ECVRF that compatible with [Chaink VRF's verifier in Solidity](https://github.com/orochi-network/smart-contracts/blob/main/contracts/libraries/VRF.sol).

## Usage

```rust
use libecvrf::{
    extends::ScalarExtend,
    secp256k1::{curve::Scalar, SecretKey},
    util::thread_rng,
    ECVRF,
};

fn main() {
    let secret_key = SecretKey::random(&mut thread_rng());
    let ecvrf = ECVRF::new(secret_key);
    let alpha = Scalar::randomize();

    let proof = ecvrf.prove(&alpha);
    println!("result: {:#?}", proof);

    println!("{:?}", ecvrf.verify(&alpha, &proof));

    let smart_contract_proof = ecvrf.prove_contract(&alpha);

    println!("result: {:#?}", smart_contract_proof);
}
```

## License

This project licensed under the [Apache License, Version 2.0](LICENSE).

_build with ❤️ and 🦀_
