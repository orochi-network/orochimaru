// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

error NotEnougCollateral(uint256 balance, uint256 requiredCollateral);
error InvalidCaller(address callerAddress);

interface IOrandPenalty {
  // Deposit collateral for a consumer contract address
  function deposit(address consumerContract) external payable returns (bool isSuccess);

  // Withdraw all native token to receiver address
  function withdraw() external returns (bool isSuccess);

  // Get penalty fee
  function getPenaltyFee() external view returns (uint256 fee);

  // Get colateral balance
  function collateralBalance(address consumerAddress) external view returns (uint256 balance);
}
