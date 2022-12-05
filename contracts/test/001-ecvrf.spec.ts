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
  epoch: 7,
  alpha: '98e41710d9e409acf2fc272c6aee574e6febf952972f64b61bc8101b9ca5d481',
  gamma:
    '78f10f783499c1f1d8a897d06e5f319c2ed0c2d98a244f9399bf94300a247886290131f610f3d849e19143b6ccea0df5783187e2049b8fdb3afe0a5826cf5321',
  c: '108579fbc389ffba2df861bb2ff17b13b9fe901b8d85559e6949eebdeb4f8acc',
  s: '47747d8b6b8bef5fdb686aa9c9377e36ce2528db54eed41b02b950e8ecaf77fb',
  y: '106a2627931e2befd150a5f18273513d7a6fcaab5628db3f6c418bf3214b67e4',
  witness_address: '98ac407c2504b160511e7f72f03ccdbbac494525',
  witness_gamma:
    'daeb114e199c5dc23d134875520d4dddcd87a9fc945dcf979c9e60d872eef4bdf8f98e466da99c2bea10e0c07a6bf4b64789c70d9f2dec3e4d2ca603cc9c97c2',
  witness_hash:
    '274dee085b24987210716e648742da540d1d7f5f53b327aafad7c1853f9bdf78b7e1bfe4b64e05368970624b728ee160170cb7a9fd263e26ec7ec8bce5b94962',
  invert_z: '61b69c5647ef42c4e7028617d9f5ac2cbd2cfd6f38a854ca7356dd8464abcdbb',
  created_date: '2022-12-05 10:16:32',
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

  it('Hash to curve mut be on the curve', async () => {
    const [x, y] = await orochiECVRF.hashToCurvePrefix(optimus.pk as any, optimus.seed);
    console.log(`\thashToCurvePrefix()\n \tx: ${x.toHexString()}\n \ty: ${y.toHexString()}`);
    expect(x.toHexString()).to.eq('0x8ea3616f712ed32f37c2f2a74d8af36f7d6bfd4c16a9d65d0aed5658ef42e68d');
    expect(y.toHexString()).to.eq('0x319dc9960a02cb1a61a6688daafd03db8ab4c9416d36aad721225671972c12b0');
  });

  /*it('Hash to curve mut be on the curve', async () => {
    const output = await orochiECVRF.verifyProof(optimus as any, optimus.seed);
    console.log(`\tverifyProof()\n \toutput: ${await output.toHexString()}`);
  });*/
});
