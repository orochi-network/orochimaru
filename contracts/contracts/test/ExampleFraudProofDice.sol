// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '../interfaces/IOrandPenalty.sol';
import './ExampleValidityProofDice.sol';

// Fraud proof is the same to
contract ExampleFraudProofDice is ExampleValidityProofDice {
  // Constructor
  constructor(address provider, uint256 limitBatching) ExampleValidityProofDice(provider, limitBatching) {}

  // We MUST allowed this smart contract to receive native token
  receive() external payable {}

  // Withdraw your collateral in OrandProviderV1
  // After withdraw collateral, you won't be able to use fraud proof
  function withdraw() external onlyOwner {
    IOrandPenalty(_getProvider()).withdraw();
    // Transfer everything to the owner
    payable(msg.sender).transfer(address(this).balance);
  }

  // Deposit collateral to enable fraud proof
  function deposit() external payable onlyOwner {
    IOrandPenalty(_getProvider()).deposit{ value: msg.value }(address(this));
  }
}
