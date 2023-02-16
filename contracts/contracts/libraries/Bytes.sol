// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.4 <0.9.0;
pragma abicoder v2;

error InvalidInputLength();
error OutOfRange();

library Bytes {
  // Convert bytes to bytes32[]
  function toBytes32Array(bytes memory input) internal pure returns (bytes32[] memory) {
    if (input.length % 32 != 0) {
      revert InvalidInputLength();
    }
    bytes32[] memory result = new bytes32[](input.length / 32);
    assembly {
      // Read length of data from offset
      let length := mload(input)

      // Seek offset to the beginning
      let offset := add(input, 0x20)

      // Next is size of chunk
      let resultOffset := add(result, 0x20)

      for {
        let i := 0
      } lt(i, length) {
        i := add(i, 0x20)
      } {
        mstore(resultOffset, mload(add(offset, i)))
        resultOffset := add(resultOffset, 0x20)
      }
    }
    return result;
  }

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
