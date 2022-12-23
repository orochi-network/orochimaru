// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';

contract OrandManagement is Ownable {
  // Public key that will be use to
  uint256[2] internal publicKey;

  // Event Set New Public Key
  event SetNewPublicKey(address indexed actor, uint256 indexed pkx, uint256 indexed pky);

  // Set public key of Orand at the constructing time
  constructor(uint256[2] memory pk) {
    _setPublicKey(pk);
  }

  //=======================[  Owner  ]====================

  // Set new public key to verify proof
  function setPublicKey(uint256[2] memory pk) external onlyOwner returns (bool) {
    return _setPublicKey(pk);
  }

  //=======================[  Internal  ]====================

  // Set new public key to verify proof
  function _setPublicKey(uint256[2] memory pk) internal returns (bool) {
    publicKey = pk;
    emit SetNewPublicKey(msg.sender, pk[0], pk[1]);
    return true;
  }

  //=======================[  External view  ]====================

  // Get public key
  function getPublicKey() external view returns (uint256[2] memory) {
    return publicKey;
  }
}
