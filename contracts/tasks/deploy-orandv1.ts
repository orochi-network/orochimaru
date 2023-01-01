/* eslint-disable no-await-in-loop */
import '@nomiclabs/hardhat-ethers';
import { BigNumber, utils } from 'ethers';
import { task } from 'hardhat/config';
import { HardhatRuntimeEnvironment } from 'hardhat/types';
import { Deployer, NATIVE_UNIT, printAllEvents } from '../helpers';
import { OrandECVRF } from '../typechain-types';
import { OrandProviderV1 } from '../typechain-types/OradProvider.sol';
import { env } from '../env';

task('deploy:orand', 'Deploy multi signature v1 contract').setAction(
  async (_taskArgs: any, hre: HardhatRuntimeEnvironment) => {
    let pk = env.OROCHI_PUBLIC_KEY.replace(/^0x/gi, '');
    let rawPubKey = {
      x: pk.substring(2, 66),
      y: pk.substring(66, 130),
    };
    let correspondingAddress = utils.getAddress(
      `0x${utils.keccak256(utils.arrayify(`0x${rawPubKey.x}${rawPubKey.y}`)).substring(26, 66)}`,
    );
    console.log(`Corresponding address: ${correspondingAddress}`);
    const accounts = await hre.ethers.getSigners();
    const deployer: Deployer = Deployer.getInstance(hre).connect(accounts[0]);
    const bigOToken = await deployer.contractDeploy('test/BigO', []);
    const orandECVRF = <OrandECVRF>await deployer.contractDeploy('OrandV1/OrandECVRF', []);
    const orandProviderV1 = <OrandProviderV1>await deployer.contractDeploy(
      'OrandV1/OrandProviderV1',
      [],
      // This public key is corresponding to 0x7e9e03a453867a7046B0277f6cD72E1B59f67a0e
      // We going to skip 0x04 -> Pubkey format from libsecp256k1
      [`0x${rawPubKey.x}`, `0x${rawPubKey.y}`],
      // Operator address
      correspondingAddress,
      orandECVRF.address,
      accounts[0].address,
      bigOToken.address,
      BigNumber.from(NATIVE_UNIT).mul(100),
    );

    deployer.printReport();
  },
);

export default {};
