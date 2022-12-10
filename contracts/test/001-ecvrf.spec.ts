import hre from 'hardhat';
import chai, { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrochiECVRF } from '../typechain-types';

let deployerSigner: SignerWithAddress;
let orochiECVRF: OrochiECVRF;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';
const record = {
  network: 56,
  epoch: 11,
  alpha: 'e96c662e45641b3ac9393fb5a7f95b726ee7c5a2619eb24e2bb53f05448317d5',
  gamma:
    '057678952884f285ad229ac203038f0e96559948477e86a9f4b870afac8b08108834b7a92ea058be982974a97a1917e9c7ac5e2cc32e5b3fa0fea3480f2f5f0b',
  c: '7d127e24cd01cb93b3d7812160ff5aef69604b1a694b485bda775326c2b165a7',
  s: '2c2dda0982a7cbce0ff568b5dec89834523936b58d2a990352a561b3efcd5f02',
  y: '602b4c7a1ce4a7089f61d2d21c8deae6515a2ca40296c103d03822aa38899eb8',
  witness_address: '047345294a9a22b356995612498c2812cf90d90b',
  witness_gamma:
    '9fc47f18f1ca3111bde979632973c23a40709e88d7e83679f68a45d2b3537f2964235037f400bcdfea212fcfbf904760c35d1366d9b891dd046a39c1a2e26c7e',
  witness_hash:
    'd0d4be404a90e3399c28d294fd0b96b8649c1f608dcc4ec136061b126ad9f0057c729e1ee4da062371fef2d9be3ccf9cf97fd89eb094de62a067db7e1bc673c3',
  inverse_z: 'e01c6d872cb3655bfdc9e9bb90dc766bdc1e9d43341e0a8c4cc00b1442ede2ac',
  created_date: '2022-12-10 07:07:03',
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
    const instanceFactory = await hre.ethers.getContractFactory('OrochiECVRF', {
      signer: deployerSigner,
    });
    orochiECVRF = <OrochiECVRF>await instanceFactory.deploy();
  });

  it('HASH_TO_CURVE_PREFIX must be on the curve', async () => {
    const [x, y] = await orochiECVRF.hashToCurvePrefix(optimus.pk as any, optimus.seed);
    console.log(`\thashToCurvePrefix()\n \tx: ${x.toHexString()}\n \ty: ${y.toHexString()}`);
    expect(x.toHexString()).to.eq('0x8eb08985a1403ef0eac3e81d264ad57c7705ef40220243f8c875b1f442ca5f94');
    expect(y.toHexString()).to.eq('0x72179fe0880780354cb355753b779c5ab68d85909521abee629ff64b43578d32');
  });

  it('elliptic curve multiple must be correct', async () => {
    const result = await orochiECVRF.ecmulVerifyWitness(optimus.gamma as any, optimus.c, optimus.cGammaWitness as any);
    expect(result).to.eq(true);
  });

  it('should able to verify the proof', async () => {
    const output = await orochiECVRF.verifyProof(optimus as any, optimus.seed);
    console.log(`\tverifyProof()\n \toutput: ${await output.toHexString()}`);
  });
});
