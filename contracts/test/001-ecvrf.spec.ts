import hre from 'hardhat';
import chai, { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrochiECVRF, OrochiECVRFDebug } from '../typechain-types';

let deployerSigner: SignerWithAddress;
let orochiECVRF: OrochiECVRF;
let orochiECVRFDebug: OrochiECVRFDebug;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';
const record = {
  network: 56,
  epoch: 15,
  alpha: '7d11f00bc5755d11e1c5723bce00f99c642980e0f833fe6248db535bbcd680e9',
  gamma:
    'd7beec35aa6d51b913b6b7414025d589f3a24aff2cd6d17e7845dafa11f701e75c556d3a72691b4fff950c6ca6d8a1c3fa13b0840b647ec174a6c727cdcbbc54',
  c: 'fcc536021c77170534ac8eb7fec865aa54bf31741ef47b4910ac1a09bb233927',
  s: '4b4ffc25764295bfd6b9117a6a4edde71d04665864a6a690584c6a19efc10d51',
  y: 'd7b732c99f5fb8314d20756a61e042d97da682a762eaed1b9a299f306e947e26',
  witness_address: '13a201f9cf17adf23ea2add73ef03a82de91a1e9',
  witness_gamma:
    'd7951c87051a699e3e05c84ccbe84bc2be8be01c240a74eaff55cfe845cd475df3db1885fc925e282c21cedee3557786270b4157b6ba13769e3af4c9b22bc786',
  witness_hash:
    '2046f2961b2ac53c046d8cae1dbb38c94da3c7dbe9e94a09eec156815730ab97029afe2d28b82de403e2cfb1264d3f9de52ce70dc607626c47739053977c5d0f',
  inverse_z: '281223608805e08ec737f88e24d1151ad55c0f3471f70001f83e0cf200d9f93f',
  created_date: '2022-12-12 09:40:50',
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

    const instanceFactoryDebug = await hre.ethers.getContractFactory('OrochiECVRFDebug', {
      signer: deployerSigner,
    });
    orochiECVRFDebug = <OrochiECVRFDebug>await instanceFactoryDebug.deploy();
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
