// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '../libraries/Bytes.sol';

contract OrandSignatureVerifier is Ownable {
  error InvalidProofLength(bytes proof);
  error InvalidProofNonce(uint256 proofNonce);
  error InvalidProofSigner(address proofSigner);

  // ECDSA proof
  struct OrandECDSAProof {
    uint96 receiverNonce;
    address receiverAddress;
    uint256 y;
  }

  // Allowed orand operator
  address internal operator;

  // Nonce value
  mapping(address => uint256) internal nonce;

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

  //=======================[  Owner  ]====================

  // Set new operator to submit proof
  function setOperator(address operatorAddress) external onlyOwner returns (bool) {
    return _setOperator(operatorAddress);
  }

  //=======================[  Internal  ]====================

  // Increasing nonce of receiver address
  function _increaseNonce(address receiverAddress) internal returns (bool) {
    nonce[receiverAddress] += 1;
    return true;
  }

  // Set proof operator
  function _setOperator(address operatorAddress) internal returns (bool) {
    emit SetNewOperator(operator, operatorAddress);
    operator = operatorAddress;
    return true;
  }

  //=======================[  Internal View ]====================

  // Decompose nonce and receiver address in signed proof
  function _decomposeProof(bytes memory proof) internal pure returns (OrandECDSAProof memory decodedProof) {
    uint256 proofUint = proof.readUint256(65);
    decodedProof.receiverNonce = uint96(proofUint >> 160);
    decodedProof.receiverAddress = address(uint160(proofUint));
    decodedProof.y = proof.readUint256(97);
    return decodedProof;
  }

  // Verify proof of operator
  function _vefifyProof(bytes memory proof) internal view returns (bool verified, OrandECDSAProof memory decodedProof) {
    if (proof.length != 129) {
      revert InvalidProofLength(proof);
    }
    bytes memory signature = proof.readBytes(0, 65);
    bytes memory message = proof.readBytes(65, proof.length);

    // Receiver Nonce || Receiver Address || y
    decodedProof = _decomposeProof(proof);

    if (uint96(nonce[decodedProof.receiverAddress]) != decodedProof.receiverNonce) {
      revert InvalidProofNonce(decodedProof.receiverNonce);
    }
    address proofSigner = message.toEthSignedMessageHash().recover(signature);
    if (proofSigner != operator) {
      revert InvalidProofSigner(proofSigner);
    }
    return (true, decodedProof);
  }

  //=======================[  External View  ]====================
  // Get signer address from a valid proof
  function checkProofSigner(
    bytes memory proof
  ) external pure returns (address signer, OrandECDSAProof memory decodedProof) {
    bytes memory signature = proof.readBytes(0, 65);
    bytes memory message = proof.readBytes(65, proof.length);
    decodedProof = _decomposeProof(proof);
    signer = message.toEthSignedMessageHash().recover(signature);
    return (signer, decodedProof);
  }

  // Get operator
  function getOperator() external view returns (address) {
    return operator;
  }

  // Get nonce
  function getNonce(address receiverAddress) external view returns (uint256) {
    return nonce[receiverAddress];
  }
}
