// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import '../libraries/Bytes.sol';

contract OrandManagement is Ownable {
  using Bytes for bytes;

  // Public key that will be use to
  uint256[2] internal publicKey;

  // Event Set New Public Key
  event SetNewPublicKey(address indexed actor, uint256 indexed pkx, uint256 indexed pky);

  // Set public key of Orand at the constructing time
  constructor(bytes memory pk) {
    _setPublicKey(pk);
  }

  //=======================[  Owner  ]====================

  // Set new public key to verify proof
  function setPublicKey(bytes memory pk) external onlyOwner returns (bool) {
    return _setPublicKey(pk);
  }

  //=======================[  Internal  ]====================

  // Set new public key to verify proof
  function _setPublicKey(bytes memory pk) internal returns (bool) {
    uint256 x = pk.readUint256(0);
    uint256 y = pk.readUint256(32);
    publicKey = [x, y];
    emit SetNewPublicKey(msg.sender, x, y);
    return true;
  }

  //=======================[  External view  ]====================

  // Get public key
  function getPublicKey() external view returns (uint256[2] memory) {
    return publicKey;
  }
}
