// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IOrandConsumerV1 {
  function consumeRandomness(uint256 randomness) external returns (bool);
}
