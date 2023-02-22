// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '../libraries/Bytes.sol';
import '../interfaces/IOrandECDSA.sol';

contract OrandECDSA is IOrandECDSA {
  // Orand operator address
  address private operator;

  // Epoch value
  mapping(address => uint256) private epoch;

  // Byte manipulation
  using Bytes for bytes;

  // Verifiy digital signature
  using ECDSA for bytes;
  using ECDSA for bytes32;

  // Event: Set New Operator
  event SetNewOperator(address indexed oldOperator, address indexed newOperator);

  // Set operator at constructing time
  constructor(address operatorAddress) {
    _setOperator(operatorAddress);
  }

  //=======================[  Internal  ]====================

  // Increasing epoch of receiver address
  function _increaseEpoch(address receiverAddress) internal {
    epoch[receiverAddress] += 1;
  }

  // Set proof operator
  function _setOperator(address operatorAddress) internal {
    emit SetNewOperator(operator, operatorAddress);
    operator = operatorAddress;
  }

  // Get epoch by receiver
  function _setTargetEpoch(OrandECDSAProof memory ecdsaProof) internal {
    epoch[ecdsaProof.receiverAddress] = ecdsaProof.receiverEpoch + 1;
  }

  //=======================[  Internal View  ]====================

  // Get epoch by receiver
  function _getTargetEpoch(address receiverAddress) internal view returns (uint96 targetEpoch) {
    return uint96(epoch[receiverAddress]);
  }

  // Get operator address
  function _getOperator() internal view returns (address operatorAddress) {
    return operator;
  }

  // Verify proof of operator
  function _decodeProof(bytes memory proof) internal pure returns (OrandECDSAProof memory ecdsaProof) {
    bytes memory signature = proof.readBytes(0, 65);
    bytes memory message = proof.readBytes(65, 64);
    uint256 proofUint = message.readUint256(0);
    ecdsaProof.receiverEpoch = uint96(proofUint >> 160);
    ecdsaProof.receiverAddress = address(uint160(proofUint));
    ecdsaProof.y = message.readUint256(32);
    ecdsaProof.signer = message.toEthSignedMessageHash().recover(signature);
    return ecdsaProof;
  }

  //=======================[  External View  ]====================

  // Get signer address from a valid proof
  function checkProofSigner(bytes memory proof) external pure returns (OrandECDSAProof memory ecdsaProof) {
    return _decodeProof(proof);
  }

  // Get operator
  function getOperator() external view returns (address operatorAddress) {
    return _getOperator();
  }

  // Get epoch by receiver address
  function getTargetEpoch(address receiverAddress) external view returns (uint96 targetEpoch) {
    return _getTargetEpoch(receiverAddress);
  }
}
