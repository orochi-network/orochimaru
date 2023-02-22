// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../libraries/Bytes.sol';

contract OrandManagement {
  using Bytes for bytes;

  // Public key that will be use to
  uint256[2] private publicKey;

  // Event Set New Public Key
  event SetNewPublicKey(address indexed actor, uint256 indexed pkx, uint256 indexed pky);

  // Set public key of Orand at the constructing time
  constructor(bytes memory pk) {
    _setPublicKey(pk);
  }

  //=======================[  Internal  ]====================

  // Set new public key to verify proof
  function _setPublicKey(bytes memory pk) internal {
    uint256 x = pk.readUint256(0);
    uint256 y = pk.readUint256(32);
    publicKey = [x, y];
    emit SetNewPublicKey(msg.sender, x, y);
  }

  //=======================[  Internal view ]====================

  function _getPublicKey() internal view returns (uint256[2] memory pubKey) {
    return publicKey;
  }

  //=======================[  External view  ]====================

  // Get public key
  function getPublicKey() external view returns (uint256[2] memory pubKey) {
    return _getPublicKey();
  }
}
