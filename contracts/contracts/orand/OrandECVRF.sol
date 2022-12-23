// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import '../libraries/VRF.sol';

contract OrandECVRF is VRF {
  //=======================[  External  ]====================
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
  ) external view returns (uint256 output) {
    verifyVRFProof(pk, gamma, c, s, alpha, uWitness, cGammaWitness, sHashWitness, zInv);
    // Encode without prefix
    output = uint256(keccak256(abi.encode(gamma)));
  }
}
