// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import './OrandManagement.sol';
import './OrandStorage.sol';
import './OrandSignatureVerifier.sol';
import './OrandPenalty.sol';
import '../interfaces/IOrandECVRF.sol';
import '../interfaces/IOrandConsumerV1.sol';

contract OrandProviderV1 is OrandStorage, OrandManagement, OrandSignatureVerifier, OrandPenalty {
  // ECVRF verifier smart contract
  IOrandECVRF ecvrf;

  // Event: Set New ECVRF Verifier
  event SetNewECVRFVerifier(address indexed actor, address indexed ecvrfAddress);

  // Provider V1 will support many consumer at once
  constructor(
    uint256[2] memory pk,
    address operator,
    address ecvrfAddress,
    address vaultAddress,
    address tokenAddress,
    uint256 penaltyAmmount
  ) OrandManagement(pk) OrandSignatureVerifier(operator) OrandPenalty(vaultAddress, tokenAddress, penaltyAmmount) {
    ecvrf = IOrandECVRF(ecvrfAddress);
  }

  function setNewECVRFVerifier(address ecvrfAddress) external onlyOwner {
    ecvrf = IOrandECVRF(ecvrfAddress);
    emit SetNewECVRFVerifier(msg.sender, ecvrfAddress);
  }

  // Publish new epoch
  function publish(bytes memory proof, EpochProof memory newEpoch) external onlyReadyForPenalty returns (bool) {
    (bool verified, address verifierAddress, uint256 y) = _vefifyProof(proof);
    require(verified, 'OP1: Invalid proof');
    require(y == newEpoch.y, 'OP1: Invalid ERCVRF output');
    require(_addEpoch(verifierAddress, newEpoch), 'OP1: Unable to add new epoch');
    require(IOrandConsumerV1(verifierAddress).consumeRandomness(newEpoch.y), 'OP1: Unable to send the randomness');
    return true;
  }

  function check() external view {}

  /**
   * @dev allow any account to sue Orochi Network and its alliance
   */
  function sue(address receiverAddress, uint256 epoch) external onlyValidEpoch(receiverAddress, epoch) {
    Epoch memory previousEpoch = storageEpoch[receiverAddress][epoch - 1];
    Epoch memory currentEpoch = storageEpoch[receiverAddress][epoch];
    // Alpha_i = Y_{i-1}
    try
      ecvrf.verifyProof(
        publicKey,
        currentEpoch.gamma,
        currentEpoch.c,
        currentEpoch.s,
        previousEpoch.y,
        currentEpoch.uWitness,
        currentEpoch.cGammaWitness,
        currentEpoch.sHashWitness,
        currentEpoch.zInv
      )
    returns (uint256 y) {
      if (currentEpoch.y == y) {
        // Everything is good
        return;
      }
    } catch {
      // Handle revert case, if reverted that meant signature is corrupted
    }
    // Apply penalty for the rest
    _penaltyOrand(msg.sender);
  }

  function getECVRFVerifier() external view returns (address) {
    return address(ecvrf);
  }
}
