/* eslint-disable no-await-in-loop */
import '@nomiclabs/hardhat-ethers';
import { task } from 'hardhat/config';
import { HardhatRuntimeEnvironment } from 'hardhat/types';
import { Deployer } from '../helpers';
import { ExampleDice } from '../typechain-types';

task('deploy:example', 'Deploy dice example contract').setAction(
  async (_taskArgs: any, hre: HardhatRuntimeEnvironment) => {
    const accounts = await hre.ethers.getSigners();
    const deployer: Deployer = Deployer.getInstance(hre).connect(accounts[0]);
    let deployedProvider;
    if (hre.network.name == 'bnbChainTest') {
      deployedProvider = '0xF3455Bb39e8C9228f8701ECb5D5A177A77096593';
    }
    <ExampleDice>await deployer.contractDeploy('OrandV1/ExampleDice', [], deployedProvider);
    deployer.printReport();
  },
);

export default {};
