// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IOrandStorage {
  // Storage form of proof
  struct Epoch {
    uint128 epoch;
    uint64 timestamp;
    uint64 sued;
    uint256 y;
    uint256[2] gamma;
    uint256 c;
    uint256 s;
    address uWitness;
    uint256[2] cGammaWitness;
    uint256[2] sHashWitness;
    uint256 zInv;
  }

  // Tranmission form of proof
  struct EpochProof {
    uint256 y;
    uint256[2] gamma;
    uint256 c;
    uint256 s;
    address uWitness;
    uint256[2] cGammaWitness;
    uint256[2] sHashWitness;
    uint256 zInv;
  }
}
