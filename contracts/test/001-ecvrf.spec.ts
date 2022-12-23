import hre from 'hardhat';
import chai, { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrochiVRF, OrochiVRFDebug } from '../typechain-types';
import { Axios } from 'axios';

let deployerSigner: SignerWithAddress;
let orochiECVRF: OrochiVRF;
let orochiECVRFDebug: OrochiVRFDebug;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';
const record = {
  network: 56,
  epoch: 18,
  alpha: '4d90d759181a1a93785a1efbf24ac3bc6617fb8b7fe5f58841dc62547bd5fa3d',
  gamma:
    'ca16dc635f333f7cd442a10e3d86a37193f0b4025cdfe3c00fffc3adc3047bdec1ce89cac5b4df21b08356c1e063fbebd3298791267d7b4d47424a17b5a40909',
  c: '4dffb09d535aafa0b7725c66d7d8e7dfa201d06dfcb2fdfc042076becb9ffa4d',
  s: '0a1cc26240a88908a45e049d7a4151415961514dac8a9d7b61645202756724fd',
  y: 'b62c15341e6d3223c5ac84e475a765a1fcb5ac122b834c2ef8ceb127142d7e85',
  witness_address: '714f1ff81445e2a21eaa820494c47f2bd0e4a93e',
  witness_gamma:
    '15e6ab8312878300ca776d711935d83f6bfafdba1adc7f69bcd0c8f34e5d85bb9d3f1086e9045813f87cde2892053de66dae661bb20e96aa218c9e59711a72b7',
  witness_hash:
    '30b6f0dae6ab3985055cf33352c0b291eb754d791de5dbfc2e3e11182935645eeb1efad8d1651dfa5c0b9b295091ba8221347de66784ec340dfa7532b7343547',
  inverse_z: 'ff174a57e0aa034c870ceaae3b06608fb543bec93e8dc3ca24d2e0beae3fcf0e',
  created_date: '2022-12-13 02:35:25',
};

const optimus = ((e) => {
  return {
    pk: [`0x${pk.substring(2, 66)}`, `0x${pk.substring(66, 130)}`],
    seed: `0x${e.alpha}`,
    gamma: [`0x${e.gamma.substring(0, 64)}`, `0x${e.gamma.substring(64, 128)}`],
    c: `0x${e.c}`,
    s: `0x${e.s}`,
    uWitness: `0x${e.witness_address}`,
    cGammaWitness: [`0x${e.witness_gamma.substring(0, 64)}`, `0x${e.witness_gamma.substring(64, 128)}`],
    sHashWitness: [`0x${e.witness_hash.substring(0, 64)}`, `0x${e.witness_hash.substring(64, 128)}`],
    zInv: `0x${e.inverse_z}`,
  };
})(record);

describe('Orochi ECVRF', function () {
  it('Orochi ECVRF must be deployed correctly', async () => {
    [deployerSigner] = await hre.ethers.getSigners();
    const instanceFactory = await hre.ethers.getContractFactory('OrochiVRF', {
      signer: deployerSigner,
    });
    orochiECVRF = <OrochiVRF>await instanceFactory.deploy();

    const instanceFactoryDebug = await hre.ethers.getContractFactory('OrochiVRFDebug', {
      signer: deployerSigner,
    });
    orochiECVRFDebug = <OrochiVRFDebug>await instanceFactoryDebug.deploy();
  });

  it('HASH_TO_CURVE_PREFIX must be on the curve', async () => {
    const [x, y] = await orochiECVRF.hashToCurvePrefix(
      [
        '0x46b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e',
        '0x9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846',
      ],
      '0xe96c662e45641b3ac9393fb5a7f95b726ee7c5a2619eb24e2bb53f05448317d5',
    );
    console.log(`\thashToCurvePrefix()\n\t x: ${x.toHexString()}\n\t y: ${y.toHexString()}`);
    expect(x.toHexString()).to.eq('0x8eb08985a1403ef0eac3e81d264ad57c7705ef40220243f8c875b1f442ca5f94');
    expect(y.toHexString()).to.eq('0x72179fe0880780354cb355753b779c5ab68d85909521abee629ff64b43578d32');
  });

  it('special case must passed', async () => {
    const result = await orochiECVRF.ecmulVerifyWitness(
      [
        '0x72b44afdcb89ba3fa7c434a01f7df3efe0805e1af6ad99480a079c8ba03ae64e',
        '0x115a786dea909f874592d36b06c780f3c0bf2ff343bd721509555ef548df755c',
      ],
      '0xb0c2a2ebcab6e463d093567f1d5cc76ad44303c10cbbfe3d09d5b4cf438d9e5c',
      [
        '0x433fa9e533d745613750ac2aecce2d6b15d649e3e4c3d62781ca4b38038a69b1',
        '0x0a4522f9db23241769d64fddce6f2f518b9a4c0080e79098a0559d82d0ed1579',
      ],
    );
    expect(result).to.eq(true);
  });

  it('special case hash to curve must passed', async () => {
    const [x, y] = await orochiECVRF.hashToCurvePrefix(
      [
        '0x46b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e',
        '0x9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846',
      ],
      '0x897eef82f83faea38e28d29e883a74c926b80c5b6e4867b6fe1d67880916e4f8',
    );
    console.log(`\thashToCurvePrefix()\n\t x: ${x.toHexString()}\n\t y: ${y.toHexString()}`);
    expect(x.toHexString()).to.eq('0xc144742e3f3d055b547be327eaf4bf8170bab15ceae4d58fee23ece70e9f83be');
    expect(y.toHexString()).to.eq('0xa63fb387153859f83b1c30d292e662649f6a74a166706faa3a10f7464d68879a');
  });

  it('elliptic curve multiple must be correct', async () => {
    const result = await orochiECVRF.ecmulVerifyWitness(optimus.gamma as any, optimus.c, optimus.cGammaWitness as any);
    expect(result).to.eq(true);
  });

  it('should able to verify the proof', async () => {
    const output = await orochiECVRF.verifyProof(optimus as any, optimus.seed);
    console.log(`\tverifyProof() -> output: ${await output.toHexString()}`);
  });
});
