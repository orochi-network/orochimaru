import hre from 'hardhat';
import { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrandECVRF } from '../typechain-types';
import { Deployer } from '../helpers';
import { OrandProviderV1 } from '../typechain-types/';
import { utils } from 'ethers';

let deployerSigner: SignerWithAddress;
let orandECVRF: OrandECVRF;
let orandProviderV1: OrandProviderV1;
let deployer: Deployer;
let somebody: SignerWithAddress;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';

const epochs = [
  {
    epoch: 0,
    alpha: '0e1e7e382020781f47c56cb161fbd088729bbf977792e8c149a496400f07d31f',
    gamma:
      '0cfb95e2d50c67f06f52189bf13da9a15b0727feb6aa5ebe376be28dbe06f09c308a9742b00bed515f20075abe82b2ff7ee4714f195f4f9d3d6e213b0d6d0426',
    c: '4e3498d44ac1133de4bae554e6b6ad895c9afdcfd7e2d765bdd9ab10875fd641',
    s: '4e22ff32cce0314887d04f011a02fe02ab1f9257ea28fbaf3a39f9e757a8679d',
    y: '8597ef3fafdf2e593f66d0e1b6133dd2e7fb3d0cbbf702c0c72bdad7ae383139',
    witnessAddress: 'dcd0d2c41d902523c01e0d7898d9ae06578a41f3',
    witnessGamma:
      '4aa481c53f06061f6961ff02536553e3577753d3ed17117ceb9fe759446a1daa23fbc69f2801adfdc4f38959160f5db0605837411f8b7ba8a765cf0f0d58881b',
    witnessHash:
      'b5168ce47b4f44feb237110135e15c8da137cb68370fe4569186b5ce1edd106a9bd47eff0b5e2ed9945ffcbd2a0870dd6f8d51a881624ac4509d1c66f91eebe2',
    inverseZ: '9fdadba6602048d7d6a6a2f08b2a33f1127da289d37510311966f87f9f4e7b75',
    signatureProof:
      '7789525b0b7f5fbfc87aa187a0a89a98f87edc7a08c244f1a6e36471cead96355212e05548f5e7b47cd6b3769978582604e8fc7be9fb12e36ca5a42d9d3149071c00000000000000000000000066681298bbbdf30a0b3ec98cabf41aa7669dc2008597ef3fafdf2e593f66d0e1b6133dd2e7fb3d0cbbf702c0c72bdad7ae383139',
    createdDate: '2023-02-20 07:49:14',
  },
  {
    epoch: 1,
    alpha: '8597ef3fafdf2e593f66d0e1b6133dd2e7fb3d0cbbf702c0c72bdad7ae383139',
    gamma:
      'b33e0a062a9e0305ab49f312d6f5d18c64b93c52b6446c99a4554712f093874039b57820072433305175a3ccaf9e9ad254a1c34cc642b4698bf63d4f38056d75',
    c: 'f62240c2cfa0de038665c00c233d0edca52f9cac41b457032f4b247d56f597c5',
    s: 'dc0acdb466632e4ddbb3ea64ea10991df53bf8bef7f76e668eeeac486ef3dfab',
    y: 'eef31a865c8f1d6eddd3454ef308294716dbd358f440ffa4da486d124e0dacbf',
    witnessAddress: '312e35807b04a7da24e8a0ba42cdfd0154031b5b',
    witnessGamma:
      '3f16e58ce46c4073a298b0aa3bc7db1eecf477e65d749f8da28262eb2deaf825c7648584e5342fa9c8fcdacc3baaee4b558d254d0ae8d686248ba38961a07ebb',
    witnessHash:
      'af48183cd69c9e14da2b5a4ef84f483b393802afaf5e89e392a301865da05a88a9ea54b273385e31d5d030299b1c818093db52c5568919db8e481dcf50bbfd99',
    inverseZ: '48723e72091bb003e7f642e026c1f4a2b506660883eabde08e11ded75afee5f9',
    signatureProof:
      '291812b956c636a3c260913215c8682f12cda35f67891434c3e6197f8b7799ce4d7de3c4cd062b9b44f36cf16aa17d3f7add4165d9c46c43053f4dba5dd803d61b00000000000000000000000166681298bbbdf30a0b3ec98cabf41aa7669dc200eef31a865c8f1d6eddd3454ef308294716dbd358f440ffa4da486d124e0dacbf',
    createdDate: '2023-02-20 07:49:15',
  },
  {
    epoch: 2,
    alpha: 'eef31a865c8f1d6eddd3454ef308294716dbd358f440ffa4da486d124e0dacbf',
    gamma:
      '6875154cc98f50fcadcad276e6650b71861de058c313486e166a464b01d3fcfbd35d3e82e1b2c14d40facb5feb1fd0e2ebb30cf4b2307c748ac4c19952cf7fe5',
    c: 'ea010c2f937af33f83b39d0da459842f8c95885b5a157530e35492e5eb0ddf43',
    s: 'd3c818d995cc933173cb140fbcbe38b2620c9c50188af0a46f6e42857c0eeefe',
    y: 'ea538ab81b86e75bf5afefba18aad191c920f0ef6cc35f849faa2b508728fa16',
    witnessAddress: 'b86fb34c8974a1bfb2a3a204333da09e7724da29',
    witnessGamma:
      'e2eae97c28219d2029d74dbca1d77c6340d75f1efa74235786d2a306e096964d2aa04e468dcb2089c33f16d90e3812d2afb3f18b9c4087b09ac38f6ecc240478',
    witnessHash:
      '2d2b3d6a8f24d4cc0b57c5354c851cae6b5a7666bd65508c577c523f02d9df585e2de9addc0e0d204e0371644583f99ba706c69937f59815b8b33532b452fc75',
    inverseZ: 'ca15128174a0ac9444b63891a1394fd555e309ad70e5efb4f4a04ad3526afe0f',
    signatureProof:
      '837e0968112fb3139685511235dd6b99c08911e2f9ef0d128d056b4fd7db74b94453195b404f7819c7e19ebb99f0bf6d2496337e0f8d7fee9512f7eab858ec491b00000000000000000000000266681298bbbdf30a0b3ec98cabf41aa7669dc200ea538ab81b86e75bf5afefba18aad191c920f0ef6cc35f849faa2b508728fa16',
    createdDate: '2023-02-20 07:49:15',
  },
];
const optimus = (e: any) => {
  return [
    `0x${e.signatureProof}`,
    <any>{
      y: `0x${e.y}`,
      gamma: [`0x${e.gamma.substring(0, 64)}`, `0x${e.gamma.substring(64, 128)}`],
      c: `0x${e.c}`,
      s: `0x${e.s}`,
      uWitness: `0x${e.witnessAddress}`,
      cGammaWitness: [`0x${e.witnessGamma.substring(0, 64)}`, `0x${e.witnessGamma.substring(64, 128)}`],
      sHashWitness: [`0x${e.witnessHash.substring(0, 64)}`, `0x${e.witnessHash.substring(64, 128)}`],
      zInv: `0x${e.inverseZ}`,
    },
  ];
};

const optimus2 = (e: any) => {
  return [
    `0x${e.signatureProof}`,
    `0x${[e.y, e.gamma, e.c, e.s, e.witnessAddress, e.witnessGamma, e.witnessHash, e.inverseZ].join('')}`,
  ];
};

const toEcvrfProof = (e: any) => {
  return <any>{
    pk: [`0x${pk.substring(2, 66)}`, `0x${pk.substring(66, 130)}`],
    gamma: [`0x${e.gamma.substring(0, 64)}`, `0x${e.gamma.substring(64, 128)}`],
    alpha: `0x${e.alpha}`,
    c: `0x${e.c}`,
    s: `0x${e.s}`,
    uWitness: `0x${e.witnessAddress}`,
    cGammaWitness: [`0x${e.witnessGamma.substring(0, 64)}`, `0x${e.witnessGamma.substring(64, 128)}`],
    sHashWitness: [`0x${e.witnessHash.substring(0, 64)}`, `0x${e.witnessHash.substring(64, 128)}`],
    zInv: `0x${e.inverseZ}`,
  };
};

const toEcvrfProof2 = (e: any) => {
  return `0x${[
    pk.substring(2, 130),
    e.gamma,
    e.alpha,
    e.c,
    e.s,
    e.witnessAddress,
    e.witnessGamma,
    e.witnessHash,
    e.inverseZ,
  ].join()}`;
};

describe('OrandProviderV1', function () {
  it('orand proof must be correct', async () => {
    [deployerSigner, somebody] = await hre.ethers.getSigners();
    deployer = Deployer.getInstance(hre).connect(deployerSigner);
    let rawPubKey = {
      x: pk.substring(2, 66),
      y: pk.substring(66, 130),
    };
    let correspondingAddress = utils.getAddress(
      `0x${utils.keccak256(utils.arrayify(`0x${rawPubKey.x}${rawPubKey.y}`)).substring(26, 66)}`,
    );
    console.log(`Corresponding address: ${correspondingAddress}`);
    // const bigOToken = <BigO>await deployer.contractDeploy('test/BigO', []);
    orandECVRF = <OrandECVRF>await deployer.contractDeploy('OrandV1/OrandECVRF', []);
    orandProviderV1 = <OrandProviderV1>await deployer.contractDeploy(
      'OrandV1/OrandProviderV1',
      [],
      // This public key is corresponding to 0x7e9e03a453867a7046B0277f6cD72E1B59f67a0e
      // We going to skip 0x04 -> Pubkey format from libsecp256k1
      `0x${pk.substring(2, 130)}`,
      // Operator address
      correspondingAddress,
      orandECVRF.address,
      1000000,
    );

    await orandProviderV1.deposit('0x66681298BBbDF30a0B3Ec98caBF41aA7669dc200', { value: 1000000000 });

    expect((await orandProviderV1.collateralBalance('0x66681298BBbDF30a0B3Ec98caBF41aA7669dc200')).toNumber()).eq(
      1000000000,
    );

    expect((await orandProviderV1.getPenaltyFee()).toNumber()).eq(1000000);

    const [signer, receiverNonce, receiverAddress, y] = await orandProviderV1.callStatic.checkProofSigner(
      `0x${epochs[0].signatureProof}`,
    );

    expect(signer).eq('0x7e9e03a453867a7046B0277f6cD72E1B59f67a0e');
    expect(receiverAddress).eq('0x66681298BBbDF30a0B3Ec98caBF41aA7669dc200');
    expect(y.toHexString().replace(/^0x/i, '')).eq(epochs[0].y);
    expect(receiverNonce.toNumber()).eq(0);
  });

  it('anyone should able to publish epoch 0 with a ECDSA + Validity proof', async () => {
    //@ts-ignore
    await orandProviderV1.connect(somebody).publishValidityProof(...optimus(epochs[0]));
  });

  it('anyone should able to publish epoch 1 with a ECDSA + Fraud proof', async () => {
    //@ts-ignore
    await orandProviderV1.connect(somebody).publishFraudProof(`0x${epochs[1].signatureProof}`);
    await orandProviderV1.switchToValidityProof(`0x${epochs[1].signatureProof}`);
  });

  it('anyone should able to publish epoch 2 with a ECDSA + Validity proof', async () => {
    //@ts-ignore
    await orandProviderV1.connect(somebody).publishValidityProof(...optimus(epochs[2]));
  });

  it('anyone should not able to sue since Orochi Network and the consumer did nothing wrong', async () => {
    expect(async () =>
      //@ts-ignore
      orandProviderV1.connect(somebody).sueFraudProof(...optimus(epochs[2])),
    ).to.revertedWithCustomError(orandProviderV1, 'EverythingIsCorrect');
  });

  it('epoch 0 and 1 should be liked', async () => {
    const proof0 = toEcvrfProof(epochs[0]);
    const proof1 = toEcvrfProof(epochs[1]);
    const result0 = await orandECVRF.verifyProof(proof0.pk, proof0.alpha, optimus(epochs[0])[1]);
    const result1 = await orandECVRF.verifyProof(proof1.pk, proof1.alpha, optimus(epochs[1])[1]);
    expect(result0.toHexString()).eq(`0x${epochs[0].y}`);
    expect(result1.toHexString()).eq(`0x${epochs[1].y}`);
    expect(result0.toHexString()).eq(`0x${epochs[1].alpha}`);
  });
});
