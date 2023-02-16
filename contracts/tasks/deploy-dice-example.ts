/* eslint-disable no-await-in-loop */
import '@nomiclabs/hardhat-ethers';
import { utils } from 'ethers';
import { task } from 'hardhat/config';
import { HardhatRuntimeEnvironment } from 'hardhat/types';
import { Deployer } from '../helpers';
import { ExampleDice, OrandECVRF } from '../typechain-types';
import { OrandProviderV1 } from '../typechain-types/OradProvider.sol';
import { env } from '../env';

task('deploy:example', 'Deploy dice example contract').setAction(
  async (_taskArgs: any, hre: HardhatRuntimeEnvironment) => {
    const accounts = await hre.ethers.getSigners();
    const deployer: Deployer = Deployer.getInstance(hre).connect(accounts[0]);
    let deployedProvider;
    if (hre.network.name == 'bnbChainTest') {
      deployedProvider = '0xD4Ed3f4aC98481BE3e7AAfC5D4e507c2Be5108E1';
    }
    <ExampleDice>await deployer.contractDeploy('OrandV1/ExampleDice', [], deployedProvider);
    deployer.printReport();
  },
);

export default {};
