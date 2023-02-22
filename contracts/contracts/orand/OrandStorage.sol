// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../interfaces/IOrandStorage.sol';
import '../interfaces/IOrandECDSA.sol';
import '../libraries/Bytes.sol';

contract OrandStorage is IOrandStorage, IOrandECDSA {
  using Bytes for bytes;

  // Event: New Epoch
  event NewEpoch(address indexed receiverAddress, uint256 indexed receiverEpoch, uint256 indexed randomness);

  // Storage of recent epoch's result
  mapping(address => uint256) private currentAlpha;

  // Storage of fault proof
  // 0 - Not set
  // 1 - Sued
  // else - Alpha
  mapping(uint256 => uint256) private fraudProof;

  //=======================[  Internal  ]====================

  // Packing adderss and uint96 to a single bytes32
  // 96 bits a ++ 160 bits b
  function _packing(uint96 a, address b) internal pure returns (uint256 packed) {
    assembly {
      packed := or(shl(160, a), b)
    }
  }

  //=======================[  Internal  ]====================

  // Add validity epoch
  function _setEpochResult(OrandECDSAProof memory ecdsaProof) internal {
    currentAlpha[ecdsaProof.receiverAddress] = ecdsaProof.y;
  }

  // Add validity epoch
  function _addValidityEpoch(OrandECDSAProof memory ecdsaProof) internal returns (bool) {
    emit NewEpoch(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch, ecdsaProof.y);
    currentAlpha[ecdsaProof.receiverAddress] = ecdsaProof.y;
    return true;
  }

  // Add fraud epoch
  function _addFraudEpoch(OrandECDSAProof memory ecdsaProof) internal returns (bool) {
    uint256 key = _packing(ecdsaProof.receiverEpoch, ecdsaProof.receiverAddress);
    // We won't overwite the epoch that was fulfilled or sued
    if (fraudProof[key] > 0) {
      revert CanotOverwiteEpoch(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch, ecdsaProof.y);
    }
    fraudProof[key] = ecdsaProof.y;
    emit NewEpoch(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch, ecdsaProof.y);
    return true;
  }

  // Mark a fraud proof as sued
  function _markAsSued(OrandECDSAProof memory ecdsaProof) internal {
    fraudProof[_packing(ecdsaProof.receiverEpoch, ecdsaProof.receiverAddress)] = 1;
  }

  //=======================[  Internal View  ]====================

  // Get epoch result
  function _getCurrentAlpha(address receiverAddress) internal view returns (uint256 epochAlpha) {
    return currentAlpha[receiverAddress];
  }

  // Get fraud proof
  function _getFraudProofAlpha(address receiverAddress, uint96 epoch) internal view returns (uint256 epochAlpha) {
    return fraudProof[_packing(epoch, receiverAddress)];
  }

  //=======================[  Public View  ]====================
  // Get epoch result
  function getCurrentAlpha(address receiverAddress) external view returns (uint256 epochAlpha) {
    return _getCurrentAlpha(receiverAddress);
  }

  // Get fraud proof
  function getFraudProofAlpha(address receiverAddress, uint96 epoch) external view returns (uint256 epochAlpha) {
    return _getFraudProofAlpha(receiverAddress, epoch);
  }
}
