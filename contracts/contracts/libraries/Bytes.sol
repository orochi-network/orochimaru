// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.4 <0.9.0;
pragma abicoder v2;

error OutOfRange();

library Bytes {
  // Read address from input bytes buffer
  function readAddress(bytes memory input, uint256 offset) internal pure returns (address result) {
    if (offset + 20 > input.length) {
      revert OutOfRange();
    }
    assembly {
      result := shr(96, mload(add(add(input, 0x20), offset)))
    }
    return result;
  }

  // Read uint256 from input bytes buffer
  function readUint256(bytes memory input, uint256 offset) internal pure returns (uint256 result) {
    if (offset + 32 > input.length) {
      revert OutOfRange();
    }
    assembly {
      result := mload(add(add(input, 0x20), offset))
    }
    return result;
  }

  // Read bytes from input bytes buffer
  function readBytes(bytes memory input, uint256 offset, uint256 length) internal pure returns (bytes memory) {
    if (offset + length > input.length) {
      revert OutOfRange();
    }
    bytes memory result = new bytes(length);
    assembly {
      // Seek offset to the beginning
      let seek := add(add(input, 0x20), offset)

      // Next is size of data
      let resultOffset := add(result, 0x20)

      for {
        let i := 0
      } lt(i, length) {
        i := add(i, 0x20)
      } {
        mstore(add(resultOffset, i), mload(add(seek, i)))
      }
    }
    return result;
  }
}
