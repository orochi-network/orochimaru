// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import '../interfaces/IOrandPenalty.sol';

contract OrandPenalty is IOrandPenalty {
  // Store collateral information
  mapping(address => uint256) private collateral;

  // Penalty fee
  uint256 private penaltyFee;

  // Transfer event
  event Transfer(address indexed from, address indexed to, uint256 indexed value);

  // Apply penalty
  event ApplyPenalty(address indexed plaintiff, address indexed theAccused, uint256 indexed value);

  // Set penalty
  event SetPenalty(uint256 oldPenaltyFee, uint256 newPenaltyFee);

  // Only consumer able to trigger
  modifier onlyConsumerContract() {
    if (_collateralBalance(msg.sender) == 0) {
      revert InvalidCaller(msg.sender);
    }
    _;
  }

  // Set penalty fee for consumer
  constructor(uint256 initalFee) {
    _setPenalty(initalFee);
  }

  //=======================[  Internal ]====================

  // Transfer collateral to agiven address and recude the collateral record
  function _transferCollateral(address from, address to, uint256 value) internal {
    // Transfer native token to consumer contract
    payable(address(to)).transfer(value);

    // Reduce the collateral of sender with the same amount
    collateral[from] -= value;
  }

  // Apply penalty to the accused
  function _applyPenalty(address theAccused) internal {
    address plaintiff = msg.sender;
    _transferCollateral(theAccused, plaintiff, penaltyFee);
    emit ApplyPenalty(plaintiff, theAccused, penaltyFee);
  }

  // Set the penalty amount
  function _setPenalty(uint256 newPenaltyFee) internal {
    emit SetPenalty(penaltyFee, newPenaltyFee);
    penaltyFee = newPenaltyFee;
  }

  //=======================[  External ]====================

  // Deposit collateral for a consumer contract address
  function deposit(address consumerContract) external payable returns (bool isSuccess) {
    // Increase collateral balance of comsumer
    collateral[consumerContract] += msg.value;
    emit Transfer(consumerContract, address(this), msg.value);
    return true;
  }

  // Withdraw all native token to consumer address
  function withdraw() external onlyConsumerContract returns (bool isSuccess) {
    address receiver = msg.sender;

    // Amount of native token to be withdraw
    uint256 withdrawCollateral = collateral[receiver];

    _transferCollateral(receiver, receiver, withdrawCollateral);

    // Trigger event
    emit Transfer(address(this), receiver, withdrawCollateral);

    return true;
  }

  //=======================[  Internal view ]====================

  // Get penalty fee
  function _getPenaltyFee() internal view returns (uint256 fee) {
    return penaltyFee;
  }

  // Get colateral balance
  function _collateralBalance(address consumerAddress) internal view returns (uint256 balance) {
    return collateral[consumerAddress];
  }

  //=======================[  External view ]====================

  // Get penalty fee
  function getPenaltyFee() external view returns (uint256 fee) {
    return _getPenaltyFee();
  }

  // Get colateral balance
  function collateralBalance(address consumerAddress) external view returns (uint256 balance) {
    return _collateralBalance(consumerAddress);
  }
}
