// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import './OrandManagement.sol';
import './OrandStorage.sol';
import './OrandSignatureVerifier.sol';
import '../interfaces/IOrandECVRF.sol';
import '../interfaces/IOrandProviderV1.sol';
import '../interfaces/IOrandConsumerV1.sol';
import '../libraries/Bytes.sol';

contract OrandProviderV1 is IOrandProviderV1, OrandStorage, OrandManagement, OrandSignatureVerifier {
  using Bytes for bytes;
  // ECVRF verifier smart contract
  IOrandECVRF ecvrf;

  // Event: Set New ECVRF Verifier
  event SetNewECVRFVerifier(address indexed actor, address indexed ecvrfAddress);

  // Provider V1 will support many consumers at once
  constructor(
    bytes memory pk,
    address orandAddress,
    address ecvrfAddress
  ) OrandManagement(pk) OrandSignatureVerifier(orandAddress) {
    ecvrf = IOrandECVRF(ecvrfAddress);
  }

  //=======================[  Owner  ]====================
  function setNewECVRFVerifier(address ecvrfAddress) external onlyOwner {
    ecvrf = IOrandECVRF(ecvrfAddress);
    emit SetNewECVRFVerifier(msg.sender, ecvrfAddress);
  }

  //=======================[  External  ]====================
  // Publish new epoch
  function publish(bytes memory proof, EpochProof memory newEpoch) external returns (bool) {
    (uint256 receiverNonce, address receiverAddress) = _vefifyProof(proof);
    uint256 y = uint256(keccak256(abi.encodePacked(newEpoch.gamma[0], newEpoch.gamma[1])));
    if (receiverNonce == 0) {
      _addEpoch(receiverAddress, receiverNonce, y);
    } else {
      ecvrf.verifyProof(publicKey, getPreviousAlpha(receiverAddress), newEpoch);
    }

    // Check for the existing smart contract and forward randomness to receiver
    if (receiverAddress.code.length > 0) {
      if (!IOrandConsumerV1(receiverAddress).consumeRandomness(y)) {
        revert UnableToForwardRandomness(receiverAddress, receiverNonce, y);
      }
    }

    // Increasing nonce of receiver to prevent replay attack
    if (!_increaseNonce(receiverAddress)) {
      revert UnableToIncreaseNonce();
    }
    return true;
  }

  //=======================[  External View  ]====================
  // Get address of ECVRF verifier
  function getECVRFVerifier() external view returns (address) {
    return address(ecvrf);
  }
}
