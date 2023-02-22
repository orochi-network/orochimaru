// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../libraries/VRF.sol';
import '../interfaces/IOrandStorage.sol';

contract OrandECVRF is VRF, IOrandStorage {
  //=======================[  External View  ]====================

  // Verify ECVRF proof
  function verifyProof(
    uint256[2] memory pk,
    uint256 alpha,
    ECVRFEpochProof memory epoch
  ) external view returns (uint256 epochResult) {
    verifyVRFProof(
      pk,
      epoch.gamma,
      epoch.c,
      epoch.s,
      alpha,
      epoch.uWitness,
      epoch.cGammaWitness,
      epoch.sHashWitness,
      epoch.zInv
    );
    // Encode without prefix
    return uint256(keccak256(abi.encode(epoch.gamma)));
  }
}
