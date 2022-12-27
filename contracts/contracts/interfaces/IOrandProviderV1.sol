// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import './IOrandStorage.sol';

interface IOrandProviderV1 is IOrandStorage {
  error InvalidProof(bytes proof);
  error InvalidECVRFOutput(uint256 linkY, uint256 inputY);
  error UnableToAddNewEpoch(address receiver, EpochProof epoch);
  error UnableToForwardRandomness(address receiver, uint256 y);
  error UnableToIncreaseNonce();
  error UnableToApplyPenalty(address sender, address receiver, uint256 epoch);
}
