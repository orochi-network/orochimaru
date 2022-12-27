// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../libraries/VRF.sol';

contract OrochiVRF is VRF {
  function ecmulVerifyWitness(
    uint256[2] memory multiplicand,
    uint256 scalar,
    uint256[2] memory product
  ) external pure returns (bool verifies) {
    return ecmulVerify(multiplicand, scalar, product);
  }

  function hashToCurvePrefix(uint256[2] memory pk, uint256 input) external view returns (uint256[2] memory) {
    return hashToCurve(pk, input);
  }

  function verifyProof(Proof memory proof, uint256 alpha) external view returns (uint256 output) {
    verifyVRFProof(
      proof.pk,
      proof.gamma,
      proof.c,
      proof.s,
      alpha,
      proof.uWitness,
      proof.cGammaWitness,
      proof.sHashWitness,
      proof.zInv
    );
    output = uint256(keccak256(abi.encode('Orochi Network', proof.gamma)));
  }
}
