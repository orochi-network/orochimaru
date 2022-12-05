import hre from 'hardhat';
import chai, { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrochiECVRF } from '../typechain-types';

let deployerSigner: SignerWithAddress;
let orochiECVRF: OrochiECVRF;

const pk =
  '0493294ac85bb373848df6f451f10a7c7f98001592c192e3436d3ad891c59a75db7439e95c7376ecdb6053b77c634829876ac7c0d13d067e0da45affb488e9cb55';
const record = {
  network: 56,
  epoch: 8,
  alpha: '106a2627931e2befd150a5f18273513d7a6fcaab5628db3f6c418bf3214b67e4',
  gamma:
    '6c78a9a72b5a1e11c0215ee5505c35cf2f12aec60e39fdd744bd3facf756a2b22a95bba215983e8f06d2b334ac8d04164f0098c5b5a9ec0d938067c267231a80',
  c: '3b30a9d94140ca6221f45e7b89288e384b1144ec5f03695e3a2e1e0098395447',
  s: '5e550324818eddd9c4080850942b497f2bb5e01bc831de3340f61696ecb36f0c',
  y: '966aa2eaf718fe794a3db4428b5b3a445cad91843267925992d11f5dd8500de2',
  witness_address: '02357554c46646179abb8aa4767d21cf4ccb9338',
  witness_gamma:
    'e59e2cc9f65c389257c08f329edc8f4805b4ffc19a7df5dfa56ee39ea87ff9ca32e559c051cfcb26e808b6f0474570216ea41a45fdf15b3af0f48efb7bfa8e41',
  witness_hash:
    '67b36a0021b1228d02cd1eabca074d14317a15815bfbe64b5f888067b95525dbd907617e04a7da5bbfdc720d211299f4c97983a60ca554d1faadd4a78dfd2ebb',
  invert_z: '17d9767cacef4b054fca51fad0b0142c703b3bd8152d6019d744c74813ef819a',
  created_date: '2022-12-05 12:56:02',
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
    zInv: `0x${e.invert_z}`,
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
    expect(x.toHexString()).to.eq('0x6eb6547c9ac3f1a2f821b026f07be611bc9aaa3a4e8b01288f0a527c6e0a0237');
    expect(y.toHexString()).to.eq('0xd1ca711d58f789b646abe394117912d19c22ab159ee31854f6fcfef2449eff22');
  });

  it('elliptic curve multiple must be correct', async () => {
    const result = await orochiECVRF.ecmulVerifyWitness(optimus.gamma as any, optimus.c, optimus.cGammaWitness as any);
    expect(result).to.eq(true);
  });

  /*
  it('should able to verify the proof', async () => {
    const output = await orochiECVRF.verifyProof(optimus as any, optimus.seed);
    console.log(`\tverifyProof()\n \toutput: ${await output.toHexString()}`);
  });*/
});
