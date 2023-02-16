// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import './IOrandStorage.sol';

interface IOrandProviderV1 is IOrandStorage {
  error UnableToForwardRandomness(address receiver, uint256 nonce, uint256 y);
  error UnableToIncreaseNonce();
}
