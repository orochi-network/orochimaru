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

  // Provider V1 will support many consumers at once
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

  //=======================[  Owner  ]====================
  function setNewECVRFVerifier(address ecvrfAddress) external onlyOwner {
    ecvrf = IOrandECVRF(ecvrfAddress);
    emit SetNewECVRFVerifier(msg.sender, ecvrfAddress);
  }

  //=======================[  External  ]====================
  // Publish new epoch
  function publish(bytes memory proof, EpochProof memory newEpoch) external onlyReadyForPenalty returns (bool) {
    (bool verified, address verifierAddress, uint256 y) = _vefifyProof(proof);
    require(verified, 'OP1: Invalid proof');
    require(y == newEpoch.y, 'OP1: Invalid ERCVRF output');
    require(_addEpoch(verifierAddress, newEpoch), 'OP1: Unable to add new epoch');
    require(IOrandConsumerV1(verifierAddress).consumeRandomness(newEpoch.y), 'OP1: Unable to send the randomness');
    return true;
  }

  // @dev allow any account to sue Orochi Network and its alliance
  function sue(address receiverAddress, uint256 epoch) external onlyValidEpoch(receiverAddress, epoch) returns (bool) {
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
        return false;
      }
    } catch {
      // Handle revert case, if reverted that meant signature is corrupted
    }
    // Apply penalty for the rest
    require(_penaltyOrand(msg.sender), 'OP1: Unable to applied penalty');
    currentEpoch.sued = 1;
    storageEpoch[receiverAddress][epoch] = currentEpoch;
    emit AppliedPenalty(receiverAddress, epoch, penaltyAmount);
    return true;
  }

  //=======================[  External View  ]====================
  // Get address of ECVRF verifier
  function getECVRFVerifier() external view returns (address) {
    return address(ecvrf);
  }

  // Check a proof is valid or not
  function check(
    uint256[2] memory gamma,
    uint256 c,
    uint256 s,
    uint256 alpha,
    address uWitness,
    uint256[2] memory cGammaWitness,
    uint256[2] memory sHashWitness,
    uint256 zInv
  ) external view returns (uint256) {
    return ecvrf.verifyProof(publicKey, gamma, c, s, alpha, uWitness, cGammaWitness, sHashWitness, zInv);
  }
}
