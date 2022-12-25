export function stringToBytes32(v: string) {
  const buf = Buffer.alloc(32);
  buf.write(v);
  return `0x${buf.toString('hex')}`;
}

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

export const NATIVE_UNIT = '1000000000000000000';

export const EMPTY_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

export const MAX_UINT256 = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
