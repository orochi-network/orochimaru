// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import '../libraries/Bytes.sol';
import '../libraries/Verifier.sol';

contract OrandSignatureVerifier is Ownable {
  // Allowed orand operator
  address internal operator;

  // Nonce value
  mapping(address => uint256) internal nonce;

  // Byte manipulation
  using Bytes for bytes;

  // Verifiy digital signature
  using Verifier for bytes;

  // Event: Set New Operator
  event SetNewOperator(address indexed oldOperator, address indexed newOperator);

  // Set operator at constructing time
  constructor(address operatorAddress) {
    _setOperator(operatorAddress);
  }

  //=======================[  External  ]====================

  // Set new operator to submit proof
  function setOperator(address operatorAddress) external onlyOwner returns (bool) {
    return _setOperator(operatorAddress);
  }

  //=======================[  Internal  ]====================

  // Increasing nonce of receiver address
  function _increaseNonce(address receiverAddress) internal returns (uint256) {
    nonce[receiverAddress] += 1;
    return nonce[receiverAddress];
  }

  // Set proof operator
  function _setOperator(address operatorAddress) internal returns (bool) {
    emit SetNewOperator(operator, operatorAddress);
    operator = operatorAddress;
    return true;
  }

  //=======================[  Internal View ]====================

  // Decompose nonce and receiver address in signed proof
  function _decomposeProof(
    bytes memory proof
  ) internal pure returns (uint256 receiverNonce, address receiverAddress, uint256 y) {
    uint256 proofUint = proof.readUint256(65);
    receiverNonce = proofUint >> 160;
    receiverAddress = address(uint160(proofUint));
    y = proof.readUint256(97);
  }

  // Verify proof of operator
  function _vefifyProof(bytes memory proof) internal view returns (bool verified, address receiverAddress, uint256 y) {
    require(proof.length == 129, 'OSV: Invalid proof.length');
    bytes memory signature = proof.readBytes(0, 65);
    bytes memory message = proof.readBytes(65, proof.length);
    uint256 receiverNonce;
    // Receiver Nonce || Receiver Address || y
    (receiverNonce, receiverAddress, y) = _decomposeProof(proof);
    require(nonce[receiverAddress] == receiverNonce, 'OSV: Invalid nonce');
    require(message.verifySerialized(signature) == operator, 'OSV: Invalid operator');
    verified = true;
  }

  //=======================[  External View  ]====================

  // Get operator
  function getOperator() external view returns (address) {
    return operator;
  }

  // Get nonce
  function getNonce(address receiverAddress) external view returns (uint256) {
    return nonce[receiverAddress];
  }
}
