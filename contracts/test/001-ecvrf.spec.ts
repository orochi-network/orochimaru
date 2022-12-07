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
  epoch: 7,
  alpha: 'b3866212fe4b7e03b46c16c5b45f2d9a201cada6167e02f738831da21d895852',
  gamma:
    'e2041474892122489b637bb6c5a4a45d7fb1c3b198d314a4739f44894c4ddf2113df30cbe09df55ba1734216f0d0ee27dde8c41dae4407c5c1f6de2325ea1e01',
  c: '9a4a7ba746b1e548d8990e7bb079e8ee93ce1ad580a23aed5a3e0c8cb5b236ec',
  s: 'c66309a076e95afab55a993d136faeea123d93bc82f69789eb596d1909256215',
  y: '216facfab1a89f21fec547b377d30b0ffda4e3833bb2d2fbe00a4f93be7f029e',
  witness_address: 'fe1d94b5a77f022bcb71457b4b4f5feffb29685a',
  witness_gamma:
    '925fb8d67437ead8a978c36d7639a9b5daf5b8ffe8ca40939e6d73a2ef6fc3c4d0ffa85e03d0915d2c0fcc5df74e1bf94a91819cb58bc00cf1e4fced8392f72f',
  witness_hash:
    '99ba09f09318eaa79da47476f3ee6827f5c884acdf7549c5fd018dd0915d3fc08c05d64fa96d182d174ba4b7f200e9b76acb031dab44d945f8fd22c752ecef6a',
  inverse_z: '352b54afe7151a188282104078ad2adfb0927fbc87b6a68d14096776ab782820',
  created_date: '2022-12-07 08:40:28',
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
    expect(x.toHexString()).to.eq('0x058e60df141811e2769ca6483891de63d70af76d388beac7f2cb0e38d4123d31');
    expect(y.toHexString()).to.eq('0xb2db93da00609079acda30d69e620ec0b77471b1ccde2757fb99969ed64352d0');
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
