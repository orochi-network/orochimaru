// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import './IOrandStorage.sol';
import './IOrandECDSA.sol';

error UnableToForwardRandomness(address receiver, uint256 epoch, uint256 y);
error UnableToIncreaseEpoch();
error EverythingIsCorrect(IOrandECDSA.OrandECDSAProof ecdsaProof);
error InvalidEpoch();

interface IOrandProviderV1 is IOrandStorage, IOrandECDSA {}
