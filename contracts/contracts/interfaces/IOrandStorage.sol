// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

error CanotOverwiteEpoch(address receiverAddress, uint256 receiverEpoch, uint256 randomness);

interface IOrandStorage {
  // Tranmission form of ECVRF epoch proof
  struct ECVRFEpochProof {
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
