import hre from 'hardhat';
import { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrochiVRF, OrochiVRFDebug } from '../typechain-types';
import { Deployer } from '../helpers';

let deployerSigner: SignerWithAddress;
let orochiECVRF: OrochiVRF;
let deployer;
// let orochiECVRFDebug: OrochiVRFDebug;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';
const record = {
  network: 56,
  epoch: 21,
  alpha: 'eabe8358ea6cedc4d3759a48648631369b9fb6d1c26da3adbc26eff564e032c4',
  gamma:
    '0846c76355dec9acdbc3bc5146cfe2c5aff116cdd610130f7ce2cc8a22a323f6e47fea662f1acdcbc1bd5dbe668a65ed7d4949e4aadcbdec07adefa6230f810d',
  c: 'dd7640ebb5cf83dbbb81b9b00b67c7d09cee8570c97b9329c2564933d97f2b13',
  s: '76b2077647a864d026657539736258056eb0b832a4833294dba014c2a579d296',
  y: 'a0c64323bd3aa4c8a3a4d80f0bde8b510c1fc2c3b6631008bd1f3d0d67f4dae3',
  witness_address: '3a71452865cb8d0130319227093537b207998c34',
  witness_gamma:
    'bfb38907a586e3770477dafb940e47d28f238c8a6085ec2208d7bd9418f925bc64acfc6bc55a7655969b979735324a6b71235c998b59c09250c1b09cc45f112f',
  witness_hash:
    'f3c9f87643ca7c23e027b98e40ca688c98a047978d932571340e490f26617b0b2abf4b3d353fc02ec4c76db23e2a4b351d00ec1fc8cce93aff2de1463f5bf628',
  inverse_z: 'c294252664566a8850cd8de33809a0c44347bc1a953da31542eed735cb472b59',
  created_date: '2022-12-25 09:35:47',
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

describe('OrandECVRF', function () {
  it('Orochi ECVRF must be deployed correctly', async () => {
    [deployerSigner] = await hre.ethers.getSigners();
    deployer = Deployer.getInstance(hre).connect(deployerSigner);
    orochiECVRF = <OrochiVRF>await deployer.contractDeploy('test/OrochiVRF', []);

    // orochiECVRFDebug = <OrochiVRFDebug>await deployer.contractDeploy('test/OrochiVRFDebug', []);
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
