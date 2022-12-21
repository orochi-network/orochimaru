// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import './OrandManagement.sol';
import './OrandStorage.sol';
import './OrandSignatureVerifier.sol';
import './OrandSender.sol';

contract OrandProviderV1 is OrandStorage, OrandManagement, OrandSignatureVerifier, OrandSenderV1 {
  // Provider V1 will support many consumer at once
  constructor(uint256[2] memory pk, address operator) OrandManagement(pk) OrandSignatureVerifier(operator) {}

  // Publish new epoch
  function publish(bytes memory proof, EpochProof memory newEpoch) external returns (bool) {
    (bool verified, address verifierAddress) = _vefifyProof(proof);
    require(verified, 'OP1: Invalid proof');
    require(_addEpoch(verifierAddress, newEpoch), 'OP1: Unable to add new epoch');
    require(_sendRandomness(verifierAddress, newEpoch.y), 'OP1: Unable to send the randomness');
    return true;
  }

  /**
   * @dev allow any account to sue Orochi Network and its alliance
   */
  function sue(address receiverAddress, uint256 epoch) external onlyValidEpoch(receiverAddress, epoch) {
    Epoch memory previousEpoch = storageEpoch[receiverAddress][epoch - 1];
    Epoch memory currentEpoch = storageEpoch[receiverAddress][epoch];
    // Alpha_i = Y_{i-1}
    require(previousEpoch.y == currentEpoch.alpha, 'Alpha must matched with previous epoch');
  }
}
