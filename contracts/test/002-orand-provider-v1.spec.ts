import hre from 'hardhat';
import { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { OrandECVRF } from '../typechain-types';
import { Deployer, NATIVE_UNIT } from '../helpers';
import { OrandProviderV1 } from '../typechain-types/';
import { BigNumber, utils } from 'ethers';
import { BigO } from '../typechain-types/contracts/test/Token.sol';

let deployerSigner: SignerWithAddress;
let orandECVRF: OrandECVRF;
let orandProviderV1: OrandProviderV1;
let deployer: Deployer;
let somebody: SignerWithAddress;

const pk =
  '0446b01e9550b56f3655dbca90cfe6b31dec3ff137f825561c563444096803531e9d4f6e8329d300483a919b63843174f1fca692fc6d2c07b985f72386e4edc846';
const epoch0 = {
  epoch: 0,
  alpha: '65b68223a80a079104a807e05de6a96dff9abd0f4565c46f03383e88709eadaf',
  gamma:
    '0f0b8be7be48dd7c830538ddfe0ae98f8bc7d39e41ee92cfd21bb4d1d9eac00ce4de89f43cfc2a4541737497387b359b68006e1b393b82bf8a4127cd4af634b0',
  c: 'da43550d7eb8804f22b8191389124a48f7e83d7c59f14085dffeffa723403204',
  s: '7684943541a5c57fb0691f21be5a1af701c1421a3977aa8824e9577ef9db0c74',
  y: '3444a98d72989c0abd13131cf95596672e50bde1d476ff71aa6ce625da1801ca',
  witnessAddress: '8fe95904320a9647ccd7f9ee8abe9043d3db6c5e',
  witnessGamma:
    '984723e486699337c81ae5b0a172f5a248fab6e981411a6472089a43a1d9486ed2eddba1a2fb40f867bfa4cec10fc541c27388441ca95e99def52a43c5b0c9b9',
  witnessHash:
    '7f5b013e14a70f4db047cc56eddba865f0854a06638493367e269e0ca6220328a1f910e54935f4355b076a53090ad09b91d7cc80b260a72ec0674dee47a7330f',
  inverseZ: '601653433309a146b4ad649631b1d7e3563cdd28f4f4c6da123cca7b8084fe4a',
  signatureProof:
    '436f80df9026124a79c605b8f5b7406a1fd7a7bebdbff4532eeb6b85cc4c506e3b59df206fe9704c2a58d590530430df12fa4931e2560c60d37ed58fb0f083071c0000000000000000000000002cdfa6346e8449dd14b23706bc93d2186bc4f301',
  createdDate: '2023-02-16 07:44:19',
};

const epoch1 = {
  epoch: 1,
  alpha: '3444a98d72989c0abd13131cf95596672e50bde1d476ff71aa6ce625da1801ca',
  gamma:
    '7ee67cae027e711d9c036bb4c6b18280eac2084d7737a450127c93ac37300415350007bed8559b83f1aea29724333a726a1be6fdef64aed35c96aa10ad577635',
  c: 'd6d4fcd865f1a2e2b68f74d5edd4045da8d7cb5af53e14a93b3ba60a22ebd105',
  s: 'ec7d1e97ae729d8d6bf11d8f2a0b9157a6f2d5acb0558dee48c847acbd4ef956',
  y: '704f150179ebe5caa582ef34a46c9c39972697692054b0326af244e42769d0b9',
  witnessAddress: '1795c14dbbb225f51b6aed6858facecb34b156f8',
  witnessGamma:
    '6ad3124030a927db8d917819b0e0e5b2f8ce0b82f99c027047e18ea07a52cf80985f435921a469a5915c2a6131435c47237667d5a0fa01f392fbbf7d3f76b768',
  witnessHash:
    '104936fc09c4d80be236d9fb00076890eec0d7a863036315228962dfc5c9bf4de6b3d1a39b21825273f284b59d9beb1df8d0ebfb82ae82ef758ce7155283cf4f',
  inverseZ: 'a9413d42144d70510803cc41aeeea14867a2ca37ff7eace5c7839f5bbfafe446',
  signatureProof:
    '351d1d43d52ff1e3948e88c40dc4768b1ef7b00755086b9b2de5aa34201f7aa6463d1813b16ce43ca555bdeae01281c048b7c0483880b5180dad688479f870a51c0000000000000000000000012cdfa6346e8449dd14b23706bc93d2186bc4f301',
  createdDate: '2023-02-16 07:44:21',
};

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

describe('Orochi ECVRF', function () {
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
    );

    const [signer, receiverNonce, receiverAddress] = await orandProviderV1.callStatic.checkProofSigner(
      `0x${epoch0.signatureProof}`,
    );

    expect(signer).eq('0x7e9e03a453867a7046B0277f6cD72E1B59f67a0e');
    expect(receiverAddress).eq('0x2cdFA6346E8449Dd14B23706Bc93D2186BC4F301');
    expect(receiverNonce.toNumber()).eq(0);
  });

  it('anyone should able to publish epoch with a signed proof', async () => {
    //@ts-ignore
    await orandProviderV1.connect(somebody).publish(...optimus(epoch0));
  });

  it('anyone should able to publish epoch with a signed proof', async () => {
    //@ts-ignore
    await orandProviderV1.connect(somebody).publish(...optimus(epoch1));
  });

  it('epoch 0 and 1 should be liked', async () => {
    const proof0 = toEcvrfProof(epoch0);
    const proof1 = toEcvrfProof(epoch1);
    const result0 = await orandECVRF.verifyProof(proof0.pk, proof0.alpha, optimus(epoch0)[1]);
    const result1 = await orandECVRF.verifyProof(proof1.pk, proof1.alpha, optimus(epoch1)[1]);
    expect(result0.toHexString()).eq(`0x${epoch0.y}`);
    expect(result1.toHexString()).eq(`0x${epoch1.y}`);
    expect(result0.toHexString()).eq(`0x${epoch1.alpha}`);
  });
});
