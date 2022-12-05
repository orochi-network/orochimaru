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
  epoch: 0,
  alpha: '5edbe535ac7de33f974d8e717e5ce590cb44000459a2785c57b533bbd5d2d20e',
  gamma:
    '2efb72bf04c24c82efe2a5dc277c4f5aad00342c55713ef77c8f6af08c65bbc3729e8c9bec201f51c5a00989d810731f86303d3ec6d123c9a428cdb24207dcf8',
  c: 'a34bc311c42bc09c910cd36eb5f4acb6fdfd1202ac1f20c3a3a3f453c15972fd',
  s: '9aa193c9a46ec021745898ebe6ab67f0c969ebf53575b12728598b1e9959f029',
  y: 'b6b5c4f4b41d6d54fc1ca5d8e18032f5aab5bd3d04a2a60ba23398f239581f6d',
  witness_address: '79f96b1c1a0def2f4f54687dfc4f4b762e5e69ae',
  witness_gamma:
    '899b0d0d55796359a66e86a3bc77b7d2abd7c16e15571c808e24c640150281a1f354b68f41abee30a7f6fc42c4db7d9beaf04005755ed8bffc6f69285acd88d8',
  witness_hash:
    'c8617c7eaf21cf012032bf816f6fb76743406c09d111c6e7af5da32201a54e961758440fb828be1615a5a3d3c39b72f461b8f148413606de55e719b1660efc7f',
  inverse_z: '7b27aa7a893ac27bb732694a7b747f67101015c9ecc7eed47215882873738406',
  created_date: '2022-12-05 13:28:44',
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
    expect(x.toHexString()).to.eq('0xf8beceefa45d296742a3aef516bbb7a4ffcaff61c13b4714aaba5e5a8df2826a');
    expect(y.toHexString()).to.eq('0x34373f427e5888f49339beb583f5f320d1cda88b575db29681c90d3e934e081c');
  });

  it('elliptic curve multiple must be correct', async () => {
    const result = await orochiECVRF.ecmulVerifyWitness(optimus.gamma as any, optimus.c, optimus.cGammaWitness as any);
    expect(result).to.eq(true);
  });

  /*it('should able to verify the proof', async () => {
    const output = await orochiECVRF.verifyProof(optimus as any, optimus.seed);
    console.log(`\tverifyProof()\n \toutput: ${await output.toHexString()}`);
  });*/
});
