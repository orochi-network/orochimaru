// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OrandStorage {
  // Storage form of proof
  struct Epoch {
    uint128 epoch;
    uint128 timestamp;
    uint256 y;
    uint256[2] gamma;
    uint256 c;
    uint256 s;
    address uWitness;
    uint256[2] cGammaWitness;
    uint256[2] sHashWitness;
    uint256 zInv;
  }

  // Tranmission form of proof
  struct EpochProof {
    uint256 y;
    uint256[2] gamma;
    uint256 c;
    uint256 s;
    address uWitness;
    uint256[2] cGammaWitness;
    uint256[2] sHashWitness;
    uint256 zInv;
  }

  // Event: New Epoch
  event NewEpoch(address indexed receiverAddress, uint256 indexed epoch, uint256 indexed randomness);

  // Storage of epoch
  mapping(address => mapping(uint256 => Epoch)) internal storageEpoch;

  // Total number of epoch
  mapping(address => uint256) totalEpoch;

  // Check if epoch is valid
  modifier onlyValidEpoch(address receiverAddress, uint256 epoch) {
    require(epoch < totalEpoch[receiverAddress] && epoch >= 1, 'Invalid epoch id');
    _;
  }

  //=======================[  Internal  ]====================

  function _addEpoch(address receiverAddress, EpochProof memory newEpoch) internal returns (bool) {
    uint256 receiverEpoch = totalEpoch[receiverAddress];
    storageEpoch[receiverAddress][receiverEpoch] = Epoch({
      epoch: uint128(receiverEpoch),
      timestamp: uint128(block.timestamp),
      y: newEpoch.y,
      // Alpha of this epoch is the result of previous epoch
      // Alpha_i = Y_{i-1}
      gamma: newEpoch.gamma,
      c: newEpoch.c,
      s: newEpoch.s,
      uWitness: newEpoch.uWitness,
      cGammaWitness: newEpoch.cGammaWitness,
      sHashWitness: newEpoch.cGammaWitness,
      zInv: newEpoch.zInv
    });
    emit NewEpoch(receiverAddress, receiverEpoch, newEpoch.y);
    totalEpoch[receiverAddress] += 1;
    return true;
  }

  //=======================[  External View  ]====================

  // Get total number of epoch
  function getTotalEpoch(address receiverAddress) external view returns (uint256) {
    return totalEpoch[receiverAddress];
  }

  // Get arbitrary epoch
  function getEpoch(
    address receiverAddress,
    uint epoch
  ) external view onlyValidEpoch(receiverAddress, epoch) returns (Epoch memory) {
    return storageEpoch[receiverAddress][epoch];
  }

  // Get current epoch
  function getCurrentEpoch(address receiverAddress) external view returns (Epoch memory) {
    return storageEpoch[receiverAddress][totalEpoch[receiverAddress] - 1];
  }
}
