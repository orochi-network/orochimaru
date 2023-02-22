// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

error InvalidProofEpoch(uint96 proofEpoch);
error InvalidProofSigner(address proofSigner);
error MismatchProofResult(uint256 ecvrfY, uint256 ecdsaY);

interface IOrandECDSA {
  // Struct Orand ECDSA proof
  struct OrandECDSAProof {
    address signer;
    uint96 receiverEpoch;
    address receiverAddress;
    uint256 y;
  }
}
