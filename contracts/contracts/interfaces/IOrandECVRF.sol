// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IOrandECVRF {
  function verifyProof(
    uint256[2] memory pk,
    uint256[2] memory gamma,
    uint256 c,
    uint256 s,
    uint256 alpha,
    address uWitness,
    uint256[2] memory cGammaWitness,
    uint256[2] memory sHashWitness,
    uint256 zInv
  ) external view returns (uint256 output);
}
