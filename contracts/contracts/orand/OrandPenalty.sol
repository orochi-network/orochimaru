// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import '@openzeppelin/contracts/access/Ownable.sol';
import '@openzeppelin/contracts/token/ERC20/IERC20.sol';

error UnableToApplyPenalty(address receiver, uint256 penaltyAmount);
error NoCollateralFromVault(address vaultAddress);

contract OrandPenalty is Ownable {
  // Token vault address
  address internal vault;

  // Amount of penalty
  uint256 internal penaltyAmount;

  // Token that will be used to pay for penalty
  IERC20 internal token;

  // Event: Set new penalty and payment token
  event SetNewPenalty(address indexed vaultAddress, address indexed tokenAddress, uint256 indexed newPenalty);

  // Event: Applied penalty to Orand
  event AppliedPenalty(address receiverAddress, uint256 epoch, uint256 penaltyAmount);

  // Check if the given vault contain enough collateral
  modifier onlyReadyForPenalty() {
    if (token.allowance(vault, address(this)) < penaltyAmount) {
      revert NoCollateralFromVault(vault);
    }
    _;
  }

  constructor(address vaultAddress, address tokenAddress, uint256 tokenPenaltyAmount) {
    _setPenalty(vaultAddress, tokenAddress, tokenPenaltyAmount);
  }

  //=======================[  Owner  ]====================
  // Set the penalty
  function setPenalty(
    address vaultAddress,
    address tokenAddress,
    uint256 newPenalty
  ) external onlyOwner returns (bool) {
    _setPenalty(vaultAddress, tokenAddress, newPenalty);
    return true;
  }

  //=======================[  Internal  ]====================
  // Penaltiy participants in Orand
  function _penaltyOrand(address receiver) internal returns (bool) {
    if (!_safeTransfer(receiver, penaltyAmount)) {
      revert UnableToApplyPenalty(receiver, penaltyAmount);
    }
    return true;
  }

  // Penaltiy participants in Orand
  function _setPenalty(address vaultAddress, address tokenAddress, uint256 newPenalty) internal returns (bool) {
    emit SetNewPenalty(vaultAddress, tokenAddress, newPenalty);
    penaltyAmount = newPenalty;
    token = IERC20(tokenAddress);
    return true;
  }

  // Perform safe transfer to a given address
  function _safeTransfer(address to, uint256 value) internal returns (bool) {
    uint256 beforeBalance = token.balanceOf(to);
    token.transferFrom(vault, to, value);
    return beforeBalance + value == token.balanceOf(to);
  }

  //=======================[  External View  ]====================
  // Read the penalty information
  function getPenalty() external view returns (address vaultAddress, address tokenAddress, uint256 amount) {
    vaultAddress = vault;
    tokenAddress = address(token);
    amount = penaltyAmount;
  }
}
