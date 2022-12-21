// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import '../interfaces/OrandConsumer.sol';

contract OrandSenderV1 {
  event SendRandomness(address indexed receiverAddress, uint256 randomness);

  //=======================[  Internal  ]====================

  function _sendRandomness(address receiverAddress, uint256 randomness) internal returns (bool) {
    emit SendRandomness(receiverAddress, randomness);
    return OrandConsumerV1(receiverAddress).consumeRandomness(randomness);
  }
}
