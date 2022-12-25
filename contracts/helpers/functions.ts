import { Signer } from '@ethersproject/abstract-signer';
import crypto, { randomBytes } from 'crypto';
import { keccak256 } from 'js-sha3';
import { BigNumber, ContractTransaction } from 'ethers';
import { HardhatRuntimeEnvironment } from 'hardhat/types';

export async function unlockSigner(hre: HardhatRuntimeEnvironment, address: string): Promise<Signer> {
  await hre.network.provider.request({
    method: 'hardhat_impersonateAccount',
    params: [address],
  });
  return hre.ethers.provider.getSigner(address);
}

export function dayToSec(days: number) {
  return Math.round(days * 86400);
}

export function monthToSec(month: number) {
  return month * dayToSec(30);
}

export async function timeTravel(hre: HardhatRuntimeEnvironment, secs: number) {
  await hre.network.provider.request({
    method: 'evm_increaseTime',
    params: [secs],
  });
  await hre.network.provider.request({
    method: 'evm_mine',
    params: [],
  });
}

export function bigNumberToBytes32(b: BigNumber): Buffer {
  return Buffer.from(`${b.toHexString().replace(/^0x/i, '').padStart(64, '0')}`, 'hex');
}

export function getUint128Random(): string {
  return `0x${randomBytes(16).toString('hex')}`;
}

export function timestamp() {
  return Math.round(Date.now());
}

export function buildDigest(): { s: Buffer; h: Buffer } {
  const buf = crypto.randomBytes(32);
  // Write time stamp to last 8 bytes it's implementation of S || t
  buf.writeBigInt64BE(BigInt(timestamp()), 24);

  return {
    s: buf,
    h: Buffer.from(keccak256.create().update(buf).digest()),
  };
}

export function buildDigestArray(size: number) {
  const h = [];
  const s = [];
  const buf = crypto.randomBytes(size * 32);
  for (let i = 0; i < size; i += 1) {
    const j = i * 32;
    buf.writeBigInt64BE(BigInt(timestamp()), j + 24);
    const t = Buffer.alloc(32);
    buf.copy(t, 0, j, j + 32);
    const d = Buffer.from(keccak256.create().update(t).digest());
    s.push(t);
    h.push(d);
    d.copy(buf, j);
  }
  return {
    h,
    s,
    v: buf,
  };
}

export function randInt(start: number, end: number) {
  return start + ((Math.random() * (end - start)) >>> 0);
}

export async function getGasCost(tx: ContractTransaction) {
  console.log('\tGas cost:', (await tx.wait()).gasUsed.toString());
}

function rTrim(value: string, trim: string): string {
  if (value.length === 0) return value;
  let count = 0;
  for (let i = value.length - 1; i >= 0 && value[i] === trim; i -= 1) {
    count += 1;
  }
  return value.substr(0, value.length - count);
}

function argumentTransform(eventName: string, arg: string) {
  if (eventName === 'RecordSet' && arg.length === 66) {
    let hexString = rTrim(arg.replace(/0x/gi, ''), '0');
    hexString = hexString.length % 2 === 0 ? hexString : `${hexString}0`;
    return Buffer.from(hexString, 'hex').toString();
  }
  return arg;
}

export async function printAllEvents(tx: ContractTransaction) {
  const result = await tx.wait();
  console.log(
    result.events
      ?.map((e) => `\t${e.event}(${e.args?.map((i) => argumentTransform(e.event || '', i)).join(', ')})`)
      .join('\n'),
  );
}

export async function getCurrentBlockTimestamp(hre: HardhatRuntimeEnvironment): Promise<number> {
  return (await hre.ethers.provider.getBlock('latest')).timestamp;
}
