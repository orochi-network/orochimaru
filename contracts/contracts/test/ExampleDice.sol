// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../interfaces/IOrandConsumerV1.sol';

// Application should be an implement of IOrandConsumerV1 interface
contract ExampleDice is IOrandConsumerV1 {
  // Provider address
  address internal orandProviderV1;

  // Result of the computation process
  uint256 internal result;

  // Set new provider
  event SetProvider(address indexed oldProvider, address indexed newProvider);

  // Receive new result from Orand
  event ReceivedNewResult(uint256 indexed diceResult, uint256 indexed randomness);

  // Only allow Orand to submit result
  modifier onlyOrandProviderV1() {
    if (msg.sender != orandProviderV1) {
      revert InvalidProvider();
    }
    _;
  }

  // Constructor
  constructor(address provider) {
    orandProviderV1 = provider;
    emit SetProvider(address(0), provider);
  }

  // Consume the result of Orand V1
  function consumeRandomness(uint256 randomness) external override onlyOrandProviderV1 returns (bool) {
    // calculate dice dot
    result = (randomness % 6) + 1;
    emit ReceivedNewResult(result, randomness);
    return true;
  }

  // Get result from smart contract
  function getResult() external view returns (uint256) {
    return result;
  }
}
