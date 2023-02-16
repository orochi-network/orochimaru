// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import './IOrandStorage.sol';

interface IOrandECVRF is IOrandStorage {
  function verifyProof(
    uint256[2] memory pk,
    uint256 alpha,
    EpochProof memory epoch
  ) external view returns (uint256 output);
}
