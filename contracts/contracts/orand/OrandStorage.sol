// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../interfaces/IOrandStorage.sol';
import '../libraries/Bytes.sol';

contract OrandStorage is IOrandStorage {
  using Bytes for bytes;

  // Event: New Epoch
  event NewEpoch(address indexed receiverAddress, uint256 indexed receiverNonce, uint256 indexed randomness);

  // Storage of epoch
  mapping(address => uint256) private previousAlpha;

  //=======================[  Internal  ]====================

  function _addEpoch(address receiverAddress, uint256 receiverNonce, uint256 y) internal returns (bool) {
    emit NewEpoch(receiverAddress, receiverNonce, y);
    previousAlpha[receiverAddress] = y;
    return true;
  }

  //=======================[  Public View  ]====================
  // Get epoch result
  function getPreviousAlpha(address receiverAddress) public view returns (uint256) {
    return previousAlpha[receiverAddress];
  }
}
