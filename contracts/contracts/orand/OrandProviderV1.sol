// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import './OrandManagement.sol';
import './OrandStorage.sol';
import './OrandECDSA.sol';
import './OrandPenalty.sol';
import '../interfaces/IOrandECVRF.sol';
import '../interfaces/IOrandProviderV1.sol';
import '../interfaces/IOrandConsumerV1.sol';

contract OrandProviderV1 is Ownable, IOrandProviderV1, OrandStorage, OrandManagement, OrandECDSA, OrandPenalty {
  // ECVRF verifier smart contract
  IOrandECVRF ecvrf;

  // Event: Set New ECVRF Verifier
  event SetNewECVRFVerifier(address indexed actor, address indexed ecvrfAddress);

  // Provider V1 will support many consumers at once
  constructor(
    bytes memory pk,
    address operatorAddress,
    address ecvrfAddress,
    uint256 penaltyFee
  ) OrandManagement(pk) OrandECDSA(operatorAddress) OrandPenalty(penaltyFee) {
    ecvrf = IOrandECVRF(ecvrfAddress);
  }

  //=======================[  Owner  ]====================

  // Update new ECVRF verifier
  function setNewECVRFVerifier(address ecvrfAddress) external onlyOwner {
    ecvrf = IOrandECVRF(ecvrfAddress);
    emit SetNewECVRFVerifier(msg.sender, ecvrfAddress);
  }

  // Set new operator to submit proof
  function setOperator(address operatorAddress) external onlyOwner returns (bool) {
    _setOperator(operatorAddress);
    return true;
  }

  // Set new public key to verify proof
  function setPublicKey(bytes memory pk) external onlyOwner returns (bool) {
    _setPublicKey(pk);
    return true;
  }

  // Set the penalty amount
  function setPenalty(uint256 newPenaltyFee) external onlyOwner returns (bool) {
    _setPenalty(newPenaltyFee);
    return true;
  }

  // Set the penalty amount
  function switchToValidityProof(bytes memory proof) external onlyOwner returns (bool) {
    OrandECDSAProof memory ecdsaProof = _decodeProof(proof);
    _setEpochResult(ecdsaProof);
    _setTargetEpoch(ecdsaProof);
    return true;
  }

  //=======================[  External  ]====================

  // Publish new epoch with ECDSA + Validity ECVRF proof
  function publishValidityProof(bytes memory proof, ECVRFEpochProof memory newEpoch) external returns (bool) {
    // Output of current epoch
    uint256 y;

    OrandECDSAProof memory ecdsaProof = _decodeProof(proof);

    // Make sure that the old epoch won't be used
    if (_getTargetEpoch(ecdsaProof.receiverAddress) != ecdsaProof.receiverEpoch) {
      revert InvalidProofEpoch(ecdsaProof.receiverEpoch);
    }

    // Proof signer must be the operator
    if (_getOperator() != ecdsaProof.signer) {
      revert InvalidProofSigner(ecdsaProof.signer);
    }

    // Epoch 0 won't check the proof
    if (ecdsaProof.receiverEpoch > 0) {
      y = ecvrf.verifyProof(_getPublicKey(), _getCurrentAlpha(ecdsaProof.receiverAddress), newEpoch);
    } else {
      y = uint256(keccak256(abi.encodePacked(newEpoch.gamma[0], newEpoch.gamma[1])));
    }

    // These two value must be the same
    if (ecdsaProof.y != y) {
      revert MismatchProofResult(y, ecdsaProof.y);
    }

    // Check for the existing smart contract and forward randomness to receiver
    if (ecdsaProof.receiverAddress.code.length > 0) {
      if (!IOrandConsumerV1(ecdsaProof.receiverAddress).consumeRandomness(y)) {
        revert UnableToForwardRandomness(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch, y);
      }
    }

    // Add epoch to the chain
    _addValidityEpoch(ecdsaProof);

    // Increasing epoch of receiver to prevent replay attack
    _increaseEpoch(ecdsaProof.receiverAddress);
    return true;
  }

  // Publish new with ECDSA + Fraud proof
  function publishFraudProof(bytes memory proof) external returns (bool) {
    // Verify ECDSA proof
    OrandECDSAProof memory ecdsaProof = _decodeProof(proof);

    // Make sure that consumer have enough collateral for fraud proof
    if (_collateralBalance(ecdsaProof.receiverAddress) < _getPenaltyFee()) {
      revert NotEnougCollateral(_collateralBalance(ecdsaProof.receiverAddress), _getPenaltyFee());
    }

    // Check for the existing smart contract and forward randomness to receiver
    if (ecdsaProof.receiverAddress.code.length > 0) {
      if (!IOrandConsumerV1(ecdsaProof.receiverAddress).consumeRandomness(ecdsaProof.y)) {
        revert UnableToForwardRandomness(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch, ecdsaProof.y);
      }
    }

    // Store fraud proof
    _addFraudEpoch(ecdsaProof);

    return true;
  }

  // Allow user to sure service provider and its alliance
  function sueFraudProof(bytes memory proof, ECVRFEpochProof memory newEpoch) external returns (bool) {
    // Verify ECDSA proof
    OrandECDSAProof memory ecdsaProof = _decodeProof(proof);

    // Zero epoch can't be sue since it's genesis
    if (ecdsaProof.receiverEpoch <= 1) {
      revert InvalidEpoch();
    }

    // Try to verify ECVRF proof
    try
      ecvrf.verifyProof(
        _getPublicKey(),
        _getFraudProofAlpha(ecdsaProof.receiverAddress, ecdsaProof.receiverEpoch - 1),
        newEpoch
      )
    returns (uint256 y) {
      if (y == uint256(keccak256(abi.encodePacked(newEpoch.gamma[0], newEpoch.gamma[1])))) {
        // Everything is good Orochi Network and Orand's consumer are doing the right thing
        revert EverythingIsCorrect(ecdsaProof);
      }
    } catch {
      // If there is an error that mean ECVRF proof is invalid
    }

    // Mark the epoch as sued
    _markAsSued(ecdsaProof);

    // Apply the penalty to the accursed
    _applyPenalty(ecdsaProof.receiverAddress);

    return true;
  }

  //=======================[  External View  ]====================

  // Get address of ECVRF verifier
  function getECVRFVerifier() external view returns (address) {
    return address(ecvrf);
  }

  // Check ECVRF proof
  function checkECVRFProof(uint256 alpha, ECVRFEpochProof memory newEpoch) external view returns (uint256 epochResult) {
    return ecvrf.verifyProof(_getPublicKey(), alpha, newEpoch);
  }
}
