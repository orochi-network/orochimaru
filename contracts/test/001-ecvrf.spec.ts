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
  epoch: 10,
  alpha: '1fa113d5fda4935ae88a665d220e8483ad3303b860ba7e136cbcbf4fc5fcc865',
  gamma:
    '79f98a0e2293432b9706f33e5f21b1c656f2d6c447988efd25d8b056963354b52e7da559d4d3053ffe1d747e87b507d1b6717f26f255dd873285e7f089dcd721',
  c: '20c2b975d232b886d7f5dfb4d51a1b18372656a856e79a9a32692265e4d708cd',
  s: '69201e59f665a096c6cecde87e5b87fb1ccfb9dc5e6ec6469ac8c733cab2c891',
  y: 'e96c662e45641b3ac9393fb5a7f95b726ee7c5a2619eb24e2bb53f05448317d5',
  witness_address: 'a25a7fd42357658a32d473b4ae56f89ccabb3dfe',
  witness_gamma:
    '15abbf759fd7f595ea4c0928092147b637a495b386aee5fbe345d7434ba81df8f49acc18297b7973ea785bb7a09f8266bdd243245c5bf34d7bab484b22cae430',
  witness_hash:
    '753222d7bc194dcbc6d3cc401b73b37cd2873c45b1b7056c1803b55fa90357c3365e0d773267ce11f074b3af13da6b518b13def2217e46e3212a07de91106273',
  inverse_z: 'bae37b5568bab9da66834e6145ae0680dfcfe01ea0f9899d584472d0beffaf10',
  created_date: '2022-12-07 09:34:38',
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
    expect(x.toHexString()).to.eq('0x1b4eb2b03b4f702b8d23ffca4c19ace1b389f95c5819a4678e5fea21bd73e393');
    expect(y.toHexString()).to.eq('0x1b4eb2b03b4f702b8d23ffca4c19ace1b389f95c5819a4678e5fea21bd73e393');
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
